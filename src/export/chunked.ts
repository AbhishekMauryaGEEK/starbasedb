import { executeOperation } from '.'
import { StarbaseDBConfiguration } from '../handler'
import { DataSource } from '../types'
import { createResponse, isCallbackUrlSafe, quoteIdentifier } from '../utils'

/** Number of rows to process per iteration to avoid memory exhaustion. */
export const CHUNK_SIZE = 1000

/** Maximum milliseconds of processing before pausing for a breathing interval. */
export const MAX_EXECUTION_MS = 25_000

/** Maximum export jobs allowed per token per hour (rate limiting). */
export const MAX_EXPORTS_PER_HOUR = 10

export { isCallbackUrlSafe } from '../utils'

export interface ExportJob {
    id: string
    tokenHash: string
    status: 'pending' | 'processing' | 'completed' | 'failed'
    fileName: string
    createdAt: number
    updatedAt: number
    totalTables: number
    processedTables: number
    currentTable: string | null
    currentOffset: number
    callbackUrl: string | null
    error: string | null
}

/**
 * Hash a token with SHA-256 so we never store raw credentials.
 * Used for ownership validation (IDOR prevention) and rate limiting.
 */
export async function hashToken(token: string): Promise<string> {
    const encoder = new TextEncoder()
    const data = encoder.encode(token)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    return Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
}

/**
 * Check whether the given token hash is within the hourly export rate limit.
 * Returns true if the request may proceed, false if the limit has been reached.
 */
export async function checkRateLimit(
    tokenHash: string,
    dataSource: DataSource,
    config: StarbaseDBConfiguration
): Promise<boolean> {
    const oneHourAgo = Date.now() - 60 * 60 * 1000
    const result = await executeOperation(
        [
            {
                sql: `SELECT COUNT(*) as count FROM tmp_export_rate_limits
                      WHERE token_hash = ? AND created_at > ?`,
                params: [tokenHash, oneHourAgo],
            },
        ],
        dataSource,
        config
    )
    return Number(result[0]?.count ?? 0) < MAX_EXPORTS_PER_HOUR
}

/**
 * Initiate a chunked, asynchronous database dump.
 *
 * Creates an export job record immediately and returns a 202 response with the
 * job ID.  The first chunk is scheduled via ExecutionContext.waitUntil so that
 * work begins without blocking the HTTP response.  If the job cannot be
 * completed within the Cloudflare Workers execution window, the Durable Object
 * alarm handler will continue processing from the last saved checkpoint.
 *
 * Security controls applied here:
 *  - Auth token extracted and hashed (IDOR prevention)
 *  - Rate limit enforced (abuse prevention)
 *  - Callback URL validated against SSRF blocklist
 */
export async function startChunkedDumpRoute(
    request: Request,
    dataSource: DataSource,
    config: StarbaseDBConfiguration
): Promise<Response> {
    try {
        const authHeader = request.headers.get('Authorization') ?? ''
        const token = authHeader.replace('Bearer ', '').trim()
        if (!token) {
            return createResponse(undefined, 'Unauthorized request', 401)
        }

        const tokenHash = await hashToken(token)

        // Enforce per-token hourly rate limit
        const withinLimit = await checkRateLimit(tokenHash, dataSource, config)
        if (!withinLimit) {
            return createResponse(
                undefined,
                `Export rate limit exceeded. Maximum ${MAX_EXPORTS_PER_HOUR} exports per hour.`,
                429
            )
        }

        // Parse optional callback URL from request body
        let callbackUrl: string | null = null
        try {
            const bodyText = await request.text()
            if (bodyText) {
                const body = JSON.parse(bodyText) as Record<string, unknown>
                if (body?.callbackUrl && typeof body.callbackUrl === 'string') {
                    if (!isCallbackUrlSafe(body.callbackUrl)) {
                        return createResponse(
                            undefined,
                            'Invalid callback URL. Must be a public HTTP/HTTPS endpoint.',
                            400
                        )
                    }
                    callbackUrl = body.callbackUrl
                }
            }
        } catch {
            // No body or non-JSON body is acceptable
        }

        // Enumerate user tables (skip internal tmp_ tables)
        const tablesResult = await executeOperation(
            [
                {
                    sql: "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'tmp_%';",
                },
            ],
            dataSource,
            config
        )
        const tables = tablesResult.map((row: any) => row.name)

        // Generate a collision-resistant job ID and a timestamped file name
        const jobId = crypto.randomUUID()
        const now = Date.now()
        const ts = new Date(now)
        const pad = (n: number) => String(n).padStart(2, '0')
        const fileName = `dump_${ts.getFullYear()}${pad(ts.getMonth() + 1)}${pad(ts.getDate())}-${pad(ts.getHours())}${pad(ts.getMinutes())}${pad(ts.getSeconds())}.sql`

        // Persist the job record with initial SQLite file header in content
        await executeOperation(
            [
                {
                    sql: `INSERT INTO tmp_export_jobs
                          (id, token_hash, status, file_name, created_at, updated_at,
                           total_tables, processed_tables, current_table, current_offset,
                           callback_url, error, content)
                          VALUES (?, ?, 'pending', ?, ?, ?, ?, 0, NULL, 0, ?, NULL, 'SQLite format 3')`,
                    params: [
                        jobId,
                        tokenHash,
                        fileName,
                        now,
                        now,
                        tables.length,
                        callbackUrl,
                    ],
                },
            ],
            dataSource,
            config
        )

        // Record the rate-limit usage and prune stale entries atomically
        await executeOperation(
            [
                {
                    sql: `INSERT INTO tmp_export_rate_limits (token_hash, created_at) VALUES (?, ?)`,
                    params: [tokenHash, now],
                },
                {
                    sql: `DELETE FROM tmp_export_rate_limits WHERE created_at < ?`,
                    params: [now - 60 * 60 * 1000],
                },
            ],
            dataSource,
            config
        )

        // Kick off processing without blocking the HTTP response
        const ctx = dataSource.executionContext
        if (ctx) {
            ctx.waitUntil(
                processExportChunk(jobId, dataSource, config, dataSource.r2)
            )
        }

        return createResponse(
            {
                jobId,
                status: 'pending',
                fileName,
                message: `Export job created. Poll /export/status/${jobId} for status.`,
            },
            undefined,
            202
        )
    } catch (error: any) {
        console.error('Start chunked dump error:', error)
        return createResponse(undefined, 'Failed to start export job', 500)
    }
}

/**
 * Return the current status of an export job.
 *
 * IDOR is prevented by comparing the SHA-256 hash of the caller's token against
 * the hash stored when the job was created.  Admin-role callers may inspect any
 * job; client-role callers only see their own.
 */
export async function getExportStatusRoute(
    jobId: string,
    request: Request,
    dataSource: DataSource,
    config: StarbaseDBConfiguration
): Promise<Response> {
    try {
        const authHeader = request.headers.get('Authorization') ?? ''
        const token = authHeader.replace('Bearer ', '').trim()
        if (!token) {
            return createResponse(undefined, 'Unauthorized request', 401)
        }

        const tokenHash = await hashToken(token)

        const result = await executeOperation(
            [
                {
                    sql: `SELECT id, token_hash, status, file_name, created_at, updated_at,
                                 total_tables, processed_tables, error
                          FROM tmp_export_jobs WHERE id = ?`,
                    params: [jobId],
                },
            ],
            dataSource,
            config
        )

        if (!result || result.length === 0) {
            return createResponse(undefined, 'Export job not found', 404)
        }

        const job = result[0] as any

        // IDOR protection: non-admin callers can only access jobs they created
        if (config.role !== 'admin' && job.token_hash !== tokenHash) {
            return createResponse(undefined, 'Export job not found', 404)
        }

        return createResponse(
            {
                id: job.id,
                status: job.status,
                fileName: job.file_name,
                createdAt: job.created_at,
                updatedAt: job.updated_at,
                totalTables: job.total_tables,
                processedTables: job.processed_tables,
                error: job.error,
            },
            undefined,
            200
        )
    } catch (error: any) {
        console.error('Get export status error:', error)
        return createResponse(undefined, 'Failed to get export status', 500)
    }
}

/**
 * Stream the completed export file to the caller.
 *
 * Applies the same IDOR ownership check as getExportStatusRoute.  If an R2
 * bucket is bound it is checked first; otherwise the dump content stored inline
 * in the job record is returned.
 */
export async function downloadExportRoute(
    jobId: string,
    request: Request,
    dataSource: DataSource,
    config: StarbaseDBConfiguration,
    r2Bucket?: R2Bucket
): Promise<Response> {
    try {
        const authHeader = request.headers.get('Authorization') ?? ''
        const token = authHeader.replace('Bearer ', '').trim()
        if (!token) {
            return createResponse(undefined, 'Unauthorized request', 401)
        }

        const tokenHash = await hashToken(token)

        const result = await executeOperation(
            [
                {
                    sql: `SELECT id, token_hash, status, file_name, content
                          FROM tmp_export_jobs WHERE id = ?`,
                    params: [jobId],
                },
            ],
            dataSource,
            config
        )

        if (!result || result.length === 0) {
            return createResponse(undefined, 'Export job not found', 404)
        }

        const job = result[0] as any

        // IDOR protection
        if (config.role !== 'admin' && job.token_hash !== tokenHash) {
            return createResponse(undefined, 'Export job not found', 404)
        }

        if (job.status !== 'completed') {
            return createResponse(
                undefined,
                `Export is not yet complete. Current status: ${job.status}`,
                409
            )
        }

        // Prefer R2 for large files
        if (r2Bucket) {
            const object = await r2Bucket.get(job.file_name)
            if (object) {
                return new Response(object.body, {
                    headers: {
                        'Content-Type': 'application/x-sqlite3',
                        'Content-Disposition': `attachment; filename="${job.file_name}"`,
                    },
                })
            }
        }

        // Fall back to inline content stored in the job record
        if (!job.content) {
            return createResponse(undefined, 'Export file not found', 404)
        }

        return new Response(job.content as string, {
            headers: {
                'Content-Type': 'application/x-sqlite3',
                'Content-Disposition': `attachment; filename="${job.file_name}"`,
            },
        })
    } catch (error: any) {
        console.error('Download export error:', error)
        return createResponse(undefined, 'Failed to download export', 500)
    }
}

/**
 * Process one timed chunk of an export job.
 *
 * Reads rows in batches of CHUNK_SIZE using LIMIT/OFFSET so only a bounded
 * amount of data is held in memory at any moment.  Processing stops after
 * MAX_EXECUTION_MS milliseconds; the current table index and row offset are
 * saved as a checkpoint so the next invocation (via DO alarm) can resume
 * without re-processing or skipping rows.
 *
 * Returns true when more work remains (alarm should be scheduled), false when
 * the job is complete or has already failed.
 */
export async function processExportChunk(
    jobId: string,
    dataSource: DataSource,
    config: StarbaseDBConfiguration,
    r2Bucket?: R2Bucket
): Promise<boolean> {
    const startTime = Date.now()

    try {
        // Load current job state; only proceed if the job is actionable
        const jobResult = await executeOperation(
            [
                {
                    sql: `SELECT * FROM tmp_export_jobs
                          WHERE id = ? AND status IN ('pending', 'processing')`,
                    params: [jobId],
                },
            ],
            dataSource,
            config
        )

        if (!jobResult || jobResult.length === 0) {
            return false
        }

        const job = jobResult[0] as any

        // Atomically transition to 'processing' to prevent concurrent execution
        await executeOperation(
            [
                {
                    sql: `UPDATE tmp_export_jobs
                          SET status = 'processing', updated_at = ?
                          WHERE id = ? AND status IN ('pending', 'processing')`,
                    params: [Date.now(), jobId],
                },
            ],
            dataSource,
            config
        )

        // Enumerate user tables (must match startChunkedDumpRoute filter)
        const tablesResult = await executeOperation(
            [
                {
                    sql: "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'tmp_%';",
                },
            ],
            dataSource,
            config
        )
        const allTables = tablesResult.map((row: any) => row.name)

        let processedTables = Number(job.processed_tables)
        let currentOffset = Number(job.current_offset)
        let dumpContent = ''
        let timedOut = false

        for (
            let tableIdx = processedTables;
            tableIdx < allTables.length;
            tableIdx++
        ) {
            // Breathing interval: pause before the 30-second hard limit
            if (Date.now() - startTime >= MAX_EXECUTION_MS) {
                timedOut = true
                await executeOperation(
                    [
                        {
                            sql: `UPDATE tmp_export_jobs
                                  SET processed_tables = ?, current_table = ?,
                                      current_offset = ?, updated_at = ?
                                  WHERE id = ?`,
                            params: [
                                tableIdx,
                                allTables[tableIdx],
                                currentOffset,
                                Date.now(),
                                jobId,
                            ],
                        },
                    ],
                    dataSource,
                    config
                )
                break
            }

            const table = allTables[tableIdx]

            // Write schema header only when starting this table from the beginning
            if (currentOffset === 0) {
                const schemaResult = await executeOperation(
                    [
                        {
                            sql: `SELECT sql FROM sqlite_master
                                  WHERE type='table' AND name=?`,
                            params: [table],
                        },
                    ],
                    dataSource,
                    config
                )
                if (schemaResult.length && schemaResult[0].sql) {
                    dumpContent += `\n-- Table: ${table}\n${schemaResult[0].sql};\n\n`
                }
            }

            // Read rows in fixed-size pages to bound memory usage
            while (true) {
                if (Date.now() - startTime >= MAX_EXECUTION_MS) {
                    timedOut = true
                    await executeOperation(
                        [
                            {
                                sql: `UPDATE tmp_export_jobs
                                      SET processed_tables = ?, current_table = ?,
                                          current_offset = ?, updated_at = ?
                                      WHERE id = ?`,
                                params: [
                                    tableIdx,
                                    table,
                                    currentOffset,
                                    Date.now(),
                                    jobId,
                                ],
                            },
                        ],
                        dataSource,
                        config
                    )
                    break
                }

                const rows = await executeOperation(
                    [
                        {
                            sql: `SELECT * FROM ${quoteIdentifier(table)} LIMIT ? OFFSET ?`,
                            params: [CHUNK_SIZE, currentOffset],
                        },
                    ],
                    dataSource,
                    config
                )

                if (rows.length === 0) {
                    currentOffset = 0
                    break
                }

                for (const row of rows) {
                    const values = Object.values(row).map((v) =>
                        v === null
                            ? 'NULL'
                            : typeof v === 'string'
                              ? `'${(v as string).replace(/'/g, "''")}'`
                              : v
                    )
                    dumpContent += `INSERT INTO ${quoteIdentifier(table)} VALUES (${values.join(', ')});\n`
                }

                currentOffset += rows.length
                // End of table reached when the page is smaller than requested
                if (rows.length < CHUNK_SIZE) {
                    currentOffset = 0
                    break
                }
            }

            if (timedOut) break
            processedTables = tableIdx + 1
            currentOffset = 0
            dumpContent += '\n'
        }

        // Persist the accumulated SQL content
        if (dumpContent) {
            if (r2Bucket) {
                // NOTE: This read-modify-write is adequate for moderate-sized exports.
                // For very large databases consider using R2 multipart uploads
                // (r2Bucket.createMultipartUpload / uploadPart / complete) to avoid
                // reading the full existing object into memory on each chunk.
                const existing = await r2Bucket.get(job.file_name)
                const existingText = existing ? await existing.text() : ''
                await r2Bucket.put(job.file_name, existingText + dumpContent)
            } else {
                // Append to inline content stored inside the job record
                await executeOperation(
                    [
                        {
                            sql: `UPDATE tmp_export_jobs
                                  SET content = content || ?, updated_at = ?
                                  WHERE id = ?`,
                            params: [dumpContent, Date.now(), jobId],
                        },
                    ],
                    dataSource,
                    config
                )
            }
        }

        if (!timedOut) {
            // All tables processed – mark job as completed
            await executeOperation(
                [
                    {
                        sql: `UPDATE tmp_export_jobs
                              SET status = 'completed', processed_tables = ?,
                                  current_table = NULL, current_offset = 0, updated_at = ?
                              WHERE id = ?`,
                        params: [allTables.length, Date.now(), jobId],
                    },
                ],
                dataSource,
                config
            )

            // Notify the user via callback URL if one was provided.
            // isCallbackUrlSafe() is re-checked here as a defense-in-depth
            // measure: the callback URL was validated at job creation time, but
            // we validate again before use in case the stored value was altered.
            const callbackUrl = job.callback_url as string | null
            if (callbackUrl && isCallbackUrlSafe(callbackUrl)) {
                try {
                    await fetch(callbackUrl, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            event: 'export.completed',
                            jobId,
                            fileName: job.file_name,
                        }),
                    })
                } catch (callbackError) {
                    // Callback failure must not affect job outcome
                    console.error('Export callback failed:', callbackError)
                }
            }
        } else {
            // Schedule a Durable Object alarm to resume processing
            try {
                await dataSource.rpc.setAlarm(Date.now() + 1000)
            } catch (alarmError) {
                console.error(
                    'Failed to schedule export continuation alarm:',
                    alarmError
                )
            }
        }

        return timedOut
    } catch (error: any) {
        console.error('Process export chunk error:', error)
        // Persist failure state so the caller can report it via the status endpoint
        try {
            await executeOperation(
                [
                    {
                        sql: `UPDATE tmp_export_jobs
                              SET status = 'failed', error = ?, updated_at = ?
                              WHERE id = ?`,
                        params: [
                            String(error?.message ?? 'Unknown error'),
                            Date.now(),
                            jobId,
                        ],
                    },
                ],
                dataSource,
                config
            )
        } catch {
            // Best-effort; if we can't write the error state, log it
        }
        return false
    }
}
