import { DurableObject } from 'cloudflare:workers'
import { isCallbackUrlSafe, quoteIdentifier } from './utils'

export class StarbaseDBDurableObject extends DurableObject {
    // Durable storage for the SQL database
    public sql: SqlStorage
    // Durable storage for the instance
    public storage: DurableObjectStorage
    // Map of WebSocket connections to their corresponding session IDs
    public connections = new Map<string, WebSocket>()
    // Store the client auth token for requests back to our Worker
    private clientAuthToken: string
    // Optional R2 bucket for storing large export files
    private r2?: R2Bucket

    /**
     * The constructor is invoked once upon creation of the Durable Object, i.e. the first call to
     * 	`DurableObjectStub::get` for a given identifier (no-op constructors can be omitted)
     *
     * @param ctx - The interface for interacting with Durable Object state
     * @param env - The interface to reference bindings declared in wrangler.toml
     */
    constructor(ctx: DurableObjectState, env: Env) {
        super(ctx, env)
        this.clientAuthToken = env.CLIENT_AUTHORIZATION_TOKEN
        this.sql = ctx.storage.sql
        this.storage = ctx.storage
        this.r2 = (env as any).EXPORT_R2_BUCKET

        // Install default necessary `tmp_` tables for various features here.
        const cacheStatement = `
        CREATE TABLE IF NOT EXISTS tmp_cache (
            "id" INTEGER PRIMARY KEY AUTOINCREMENT,
            "timestamp" REAL NOT NULL,
            "ttl" INTEGER NOT NULL,
            "query" TEXT UNIQUE NOT NULL,
            "results" TEXT
        );`

        const allowlistStatement = `
        CREATE TABLE IF NOT EXISTS tmp_allowlist_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sql_statement TEXT NOT NULL,
            source TEXT DEFAULT 'external'
        )`
        const allowlistRejectedStatement = `
        CREATE TABLE IF NOT EXISTS tmp_allowlist_rejections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sql_statement TEXT NOT NULL,
            source TEXT DEFAULT 'external',
            created_at TEXT DEFAULT (datetime('now'))
        )`

        const rlsStatement = `
        CREATE TABLE IF NOT EXISTS tmp_rls_policies (
            "id" INTEGER PRIMARY KEY AUTOINCREMENT,
            "actions" TEXT NOT NULL CHECK(actions IN ('SELECT', 'UPDATE', 'INSERT', 'DELETE')),
            "schema" TEXT,
            "table" TEXT NOT NULL,
            "column" TEXT NOT NULL,
            "value" TEXT NOT NULL,
            "value_type" TEXT NOT NULL DEFAULT 'string',
            "operator" TEXT DEFAULT '='
        )`

        const exportJobsStatement = `
        CREATE TABLE IF NOT EXISTS tmp_export_jobs (
            id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            file_name TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            total_tables INTEGER NOT NULL DEFAULT 0,
            processed_tables INTEGER NOT NULL DEFAULT 0,
            current_table TEXT,
            current_offset INTEGER NOT NULL DEFAULT 0,
            callback_url TEXT,
            error TEXT,
            content TEXT
        )`

        const exportRateLimitsStatement = `
        CREATE TABLE IF NOT EXISTS tmp_export_rate_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )`

        this.executeQuery({ sql: cacheStatement })
        this.executeQuery({ sql: allowlistStatement })
        this.executeQuery({ sql: allowlistRejectedStatement })
        this.executeQuery({ sql: rlsStatement })
        this.executeQuery({ sql: exportJobsStatement })
        this.executeQuery({ sql: exportRateLimitsStatement })
    }

    init() {
        return {
            getAlarm: this.getAlarm.bind(this),
            setAlarm: this.setAlarm.bind(this),
            deleteAlarm: this.deleteAlarm.bind(this),
            getStatistics: this.getStatistics.bind(this),
            executeQuery: this.executeQuery.bind(this),
        }
    }

    public async getAlarm(): Promise<number | null> {
        return await this.storage.getAlarm()
    }

    public async setAlarm(
        scheduledTime: number | Date,
        options?: DurableObjectSetAlarmOptions
    ): Promise<void> {
        try {
            const now = Date.now()
            const inputTime =
                scheduledTime instanceof Date
                    ? scheduledTime.getTime()
                    : scheduledTime

            // Ensure the time is in the future and at least 1 second from now
            const minimumTime = now + 1000
            const finalTime = Math.max(inputTime, minimumTime)
            await this.storage.setAlarm(finalTime, options)
        } catch (e) {
            console.error('Error setting alarm: ', e)
            throw e
        }
    }

    public deleteAlarm(options?: DurableObjectSetAlarmOptions): Promise<void> {
        return this.storage.deleteAlarm(options)
    }

    async alarm() {
        // First, continue any pending export jobs before processing cron tasks.
        // Export jobs are time-sensitive and must resume from their saved checkpoint.
        const exportResumed = await this.continueExportJobs()
        if (exportResumed) {
            // More export work is still pending; do not process cron this cycle
            // so that the export alarm can fire again in ~1 second.
            return
        }

        try {
            // Fetch all the tasks that are marked to emit an event for this cycle.
            const task = (await this.executeQuery({
                sql: 'SELECT * FROM tmp_cron_tasks WHERE is_active = 1;',
                isRaw: false,
            })) as Record<string, SqlStorageValue>[]

            if (!task.length) {
                return
            }

            try {
                const firstTask = task[0]
                await fetch(`${firstTask.callback_host}/cron/callback`, {
                    method: 'POST',
                    headers: {
                        Authorization: `Bearer ${this.clientAuthToken}`,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(task ?? []),
                })
            } catch (error) {
                console.error('Failed to call the alarm/cron callback:', error)

                // If the callback fails, we should try to reschedule to prevent the chain from breaking
                try {
                    await this.setAlarm(Date.now() + 60000)
                } catch (retryError) {
                    console.error('Failed to set recovery alarm:', retryError)
                }
            }
        } catch (e) {
            console.error('There was an error processing an alarm: ', e)

            // Try to recover by scheduling a retry in 1 minute
            try {
                await this.setAlarm(Date.now() + 60000)
            } catch (retryError) {
                console.error('Failed to set recovery alarm:', retryError)
            }
        }
    }

    /**
     * Resume any export jobs that are in a 'pending' or 'processing' state.
     * Called at the start of every alarm() invocation so that large exports
     * can continue across multiple Durable Object activations.
     *
     * Returns true if an export job was found and needs more processing
     * (alarm will be rescheduled for 1 second later), false otherwise.
     */
    private async continueExportJobs(): Promise<boolean> {
        try {
            const jobs = (await this.executeQuery({
                sql: `SELECT * FROM tmp_export_jobs
                      WHERE status IN ('pending', 'processing')
                      ORDER BY created_at ASC LIMIT 1`,
                isRaw: false,
            })) as Record<string, SqlStorageValue>[]

            if (!jobs.length) {
                return false
            }

            const job = jobs[0]
            const jobId = job.id as string
            const startTime = Date.now()
            const MAX_MS = 25_000
            const CHUNK = 1000

            // Mark as processing
            await this.executeQuery({
                sql: `UPDATE tmp_export_jobs
                      SET status = 'processing', updated_at = ?
                      WHERE id = ? AND status IN ('pending', 'processing')`,
                params: [Date.now(), jobId],
            })

            // Enumerate user tables
            const tableRows = (await this.executeQuery({
                sql: "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'tmp_%';",
                isRaw: false,
            })) as Record<string, SqlStorageValue>[]
            const allTables = tableRows.map((r) => String(r.name))

            let processedTables = Number(job.processed_tables ?? 0)
            let currentOffset = Number(job.current_offset ?? 0)
            let dumpContent = ''
            let timedOut = false

            for (
                let tableIdx = processedTables;
                tableIdx < allTables.length;
                tableIdx++
            ) {
                if (Date.now() - startTime >= MAX_MS) {
                    timedOut = true
                    await this.executeQuery({
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
                    })
                    break
                }

                const table = allTables[tableIdx]

                if (currentOffset === 0) {
                    const schemaRows = (await this.executeQuery({
                        sql: `SELECT sql FROM sqlite_master WHERE type='table' AND name=?`,
                        params: [table],
                        isRaw: false,
                    })) as Record<string, SqlStorageValue>[]
                    if (schemaRows.length && schemaRows[0].sql) {
                        dumpContent += `\n-- Table: ${table}\n${schemaRows[0].sql};\n\n`
                    }
                }

                while (true) {
                    if (Date.now() - startTime >= MAX_MS) {
                        timedOut = true
                        await this.executeQuery({
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
                        })
                        break
                    }

                    const dataRows = (await this.executeQuery({
                        sql: `SELECT * FROM ${quoteIdentifier(table)} LIMIT ? OFFSET ?`,
                        params: [CHUNK, currentOffset],
                        isRaw: false,
                    })) as Record<string, SqlStorageValue>[]

                    if (dataRows.length === 0) {
                        currentOffset = 0
                        break
                    }

                    for (const row of dataRows) {
                        const values = Object.values(row).map((v) =>
                            v === null
                                ? 'NULL'
                                : typeof v === 'string'
                                  ? `'${v.replace(/'/g, "''")}'`
                                  : v
                        )
                        dumpContent += `INSERT INTO ${quoteIdentifier(table)} VALUES (${values.join(', ')});\n`
                    }

                    currentOffset += dataRows.length
                    if (dataRows.length < CHUNK) {
                        currentOffset = 0
                        break
                    }
                }

                if (timedOut) break
                processedTables = tableIdx + 1
                currentOffset = 0
                dumpContent += '\n'
            }

            if (dumpContent) {
                if (this.r2) {
                    // NOTE: Read-modify-write is adequate for moderate-sized exports.
                    // For very large databases consider R2 multipart uploads to avoid
                    // loading the full existing object into memory on each chunk.
                    const existing = await this.r2.get(String(job.file_name))
                    const existingText = existing ? await existing.text() : ''
                    await this.r2.put(
                        String(job.file_name),
                        existingText + dumpContent
                    )
                } else {
                    await this.executeQuery({
                        sql: `UPDATE tmp_export_jobs
                              SET content = content || ?, updated_at = ?
                              WHERE id = ?`,
                        params: [dumpContent, Date.now(), jobId],
                    })
                }
            }

            if (!timedOut) {
                await this.executeQuery({
                    sql: `UPDATE tmp_export_jobs
                          SET status = 'completed', processed_tables = ?,
                              current_table = NULL, current_offset = 0, updated_at = ?
                          WHERE id = ?`,
                    params: [allTables.length, Date.now(), jobId],
                })

                const callbackUrl = job.callback_url as string | null
                // Re-validate the callback URL as defense-in-depth (SSRF prevention)
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
                    } catch (err) {
                        console.error('Export callback failed:', err)
                    }
                }
                return false
            }

            // More work needed – reschedule alarm
            await this.setAlarm(Date.now() + 1000)
            return true
        } catch (e) {
            console.error('Error continuing export job:', e)
            return false
        }
    }

    public async getStatistics(): Promise<{
        databaseSize: number
        activeConnections: number
        recentQueries: number
    }> {
        const sql = `SELECT COUNT(*) as count 
            FROM tmp_query_log 
            WHERE created_at >= datetime('now', '-24 hours')`
        const result = (await this.executeQuery({
            sql,
            isRaw: false,
        })) as Record<string, SqlStorageValue>[]
        const row = result.length ? result[0] : { count: 0 }

        return {
            // Size in bytes
            databaseSize: this.sql.databaseSize,
            // Count of persistent web socket connections
            activeConnections: this.connections.size,
            // Assuming the `QueryLogPlugin` is in use, count is of the last 24 hours
            recentQueries: Number(row.count),
        }
    }

    async fetch(request: Request) {
        const url = new URL(request.url)

        if (url.pathname === '/socket') {
            if (request.headers.get('upgrade') === 'websocket') {
                const sessionId = url.searchParams.get('sessionId') ?? undefined
                return this.clientConnected(sessionId)
            }
            return new Response('Expected WebSocket', { status: 400 })
        }

        if (url.pathname === '/socket/broadcast') {
            const message = await request.json()
            const sessionId = url.searchParams.get('sessionId') ?? undefined

            // Broadcast to all connected clients using server-side sockets
            for (const [id, connection] of this.connections) {
                try {
                    // If the broadcast event included a specific sessionId then we should expect
                    // that message was intended to be broadcasted to a particular session only.
                    if (sessionId && sessionId != id) {
                        continue
                    }

                    connection.send(JSON.stringify(message))
                } catch (err) {
                    // Clean up dead connections
                    this.connections.delete(id)
                }
            }

            return new Response('Broadcast sent', { status: 200 })
        }

        return new Response('Unknown operation', { status: 400 })
    }

    public async clientConnected(sessionId?: string) {
        const webSocketPair = new WebSocketPair()
        const [client, server] = Object.values(webSocketPair)
        const wsSessionId = sessionId ?? crypto.randomUUID()

        // Store the server-side socket instead of client-side
        this.connections.set(wsSessionId, server)

        // Accept and configure the WebSocket
        server.accept()

        // Add message and error handling
        server.addEventListener('message', async (msg) => {
            await this.webSocketMessage(server, msg.data)
        })

        server.addEventListener('error', (err) => {
            console.error(`WebSocket error for ${wsSessionId}:`, err)
            this.connections.delete(wsSessionId)
        })

        return new Response(null, { status: 101, webSocket: client })
    }

    async webSocketMessage(ws: WebSocket, message: any) {
        const { sql, params, action } = JSON.parse(message)

        if (action === 'query') {
            const queries = [{ sql, params }]
            const result = await this.executeTransaction(queries, false)
            ws.send(JSON.stringify(result))
        }
    }

    async webSocketClose(
        ws: WebSocket,
        code: number,
        reason: string,
        wasClean: boolean
    ) {
        // If the client closes the connection, the runtime will invoke the webSocketClose() handler.
        ws.close(code, 'StarbaseDB is closing WebSocket connection')

        // Remove the WebSocket connection from the map
        const tags = this.ctx.getTags(ws)
        if (tags.length) {
            const wsSessionId = tags[0]
            this.connections.delete(wsSessionId)
        }
    }

    private async executeRawQuery<
        T extends Record<string, SqlStorageValue> = Record<
            string,
            SqlStorageValue
        >,
    >(opts: { sql: string; params?: unknown[] }) {
        const { sql, params } = opts

        try {
            let cursor

            if (params && params.length) {
                cursor = this.sql.exec<T>(sql, ...params)
            } else {
                cursor = this.sql.exec<T>(sql)
            }

            return cursor
        } catch (error) {
            console.error('SQL Execution Error:', error)
            throw error
        }
    }

    public async executeQuery(opts: {
        sql: string
        params?: unknown[]
        isRaw?: boolean
    }) {
        const cursor = await this.executeRawQuery(opts)

        if (opts.isRaw) {
            return {
                columns: cursor.columnNames,
                rows: Array.from(cursor.raw()),
                meta: {
                    rows_read: cursor.rowsRead,
                    rows_written: cursor.rowsWritten,
                },
            }
        }

        return cursor.toArray()
    }

    public async executeTransaction(
        queries: { sql: string; params?: unknown[] }[],
        isRaw: boolean
    ): Promise<any[]> {
        const results = []

        try {
            for (const queryObj of queries) {
                const { sql, params } = queryObj
                const result = await this.executeQuery({ sql, params, isRaw })
                results.push(result)
            }

            return results
        } catch (error) {
            console.error('Transaction Execution Error:', error)
            throw error
        }
    }
}
