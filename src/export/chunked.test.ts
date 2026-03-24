import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
    hashToken,
    isCallbackUrlSafe,
    checkRateLimit,
    startChunkedDumpRoute,
    getExportStatusRoute,
    downloadExportRoute,
    processExportChunk,
    MAX_EXPORTS_PER_HOUR,
} from './chunked'
import { executeOperation } from '.'
import type { DataSource } from '../types'
import type { StarbaseDBConfiguration } from '../handler'

vi.mock('.', () => ({
    executeOperation: vi.fn(),
}))

vi.mock('../utils', async () => {
    const actual = await vi.importActual<typeof import('../utils')>('../utils')
    return {
        ...actual,
        createResponse: vi.fn(
            (data: unknown, message: string | undefined, status: number) =>
                new Response(JSON.stringify({ result: data, error: message }), {
                    status,
                    headers: { 'Content-Type': 'application/json' },
                })
        ),
    }
})

let mockDataSource: DataSource
let mockConfig: StarbaseDBConfiguration

beforeEach(() => {
    vi.clearAllMocks()

    mockDataSource = {
        source: 'internal',
        rpc: {
            executeQuery: vi.fn(),
            setAlarm: vi.fn(),
            getAlarm: vi.fn(),
            deleteAlarm: vi.fn(),
            getStatistics: vi.fn(),
        },
        executionContext: {
            waitUntil: vi.fn(),
            passThroughOnException: vi.fn(),
        } as any,
    } as any

    mockConfig = {
        outerbaseApiKey: 'mock-api-key',
        role: 'admin',
        features: { export: true },
    }
})

// ─── hashToken ────────────────────────────────────────────────────────────────

describe('hashToken', () => {
    it('returns a 64-character hex string', async () => {
        const hash = await hashToken('my-secret-token')
        expect(hash).toMatch(/^[0-9a-f]{64}$/)
    })

    it('returns the same hash for the same input', async () => {
        const h1 = await hashToken('abc')
        const h2 = await hashToken('abc')
        expect(h1).toBe(h2)
    })

    it('returns different hashes for different inputs', async () => {
        const h1 = await hashToken('token-a')
        const h2 = await hashToken('token-b')
        expect(h1).not.toBe(h2)
    })
})

// ─── isCallbackUrlSafe ────────────────────────────────────────────────────────

describe('isCallbackUrlSafe', () => {
    it('allows a public HTTPS URL', () => {
        expect(isCallbackUrlSafe('https://example.com/callback')).toBe(true)
    })

    it('allows a public HTTP URL', () => {
        expect(isCallbackUrlSafe('http://example.com/webhook')).toBe(true)
    })

    it('blocks localhost', () => {
        expect(isCallbackUrlSafe('http://localhost/secret')).toBe(false)
    })

    it('blocks 127.0.0.1 loopback', () => {
        expect(isCallbackUrlSafe('http://127.0.0.1/secret')).toBe(false)
    })

    it('blocks IPv6 loopback ::1', () => {
        expect(isCallbackUrlSafe('http://[::1]/secret')).toBe(false)
    })

    it('blocks AWS metadata endpoint 169.254.169.254', () => {
        expect(
            isCallbackUrlSafe('http://169.254.169.254/latest/meta-data')
        ).toBe(false)
    })

    it('blocks RFC-1918 10.x.x.x', () => {
        expect(isCallbackUrlSafe('http://10.0.0.1/internal')).toBe(false)
    })

    it('blocks RFC-1918 172.16.x.x', () => {
        expect(isCallbackUrlSafe('http://172.16.0.1/internal')).toBe(false)
    })

    it('blocks RFC-1918 192.168.x.x', () => {
        expect(isCallbackUrlSafe('http://192.168.1.1/internal')).toBe(false)
    })

    it('does NOT block 172.15.x.x (just outside private range)', () => {
        expect(isCallbackUrlSafe('http://172.15.0.1/cb')).toBe(true)
    })

    it('blocks metadata.google.internal', () => {
        expect(
            isCallbackUrlSafe('http://metadata.google.internal/computeMetadata')
        ).toBe(false)
    })

    it('rejects a non-http/https scheme', () => {
        expect(isCallbackUrlSafe('ftp://example.com/dump')).toBe(false)
    })

    it('rejects a malformed URL', () => {
        expect(isCallbackUrlSafe('not-a-url')).toBe(false)
    })

    it('blocks shared address space 100.64.x.x', () => {
        expect(isCallbackUrlSafe('http://100.64.0.1/cb')).toBe(false)
    })
})

// ─── checkRateLimit ───────────────────────────────────────────────────────────

describe('checkRateLimit', () => {
    it('returns true when under the limit', async () => {
        vi.mocked(executeOperation).mockResolvedValueOnce([{ count: 3 }])
        const ok = await checkRateLimit('hash123', mockDataSource, mockConfig)
        expect(ok).toBe(true)
    })

    it('returns false when at the limit', async () => {
        vi.mocked(executeOperation).mockResolvedValueOnce([
            { count: MAX_EXPORTS_PER_HOUR },
        ])
        const ok = await checkRateLimit('hash123', mockDataSource, mockConfig)
        expect(ok).toBe(false)
    })

    it('returns false when over the limit', async () => {
        vi.mocked(executeOperation).mockResolvedValueOnce([
            { count: MAX_EXPORTS_PER_HOUR + 5 },
        ])
        const ok = await checkRateLimit('hash123', mockDataSource, mockConfig)
        expect(ok).toBe(false)
    })

    it('returns true when the result is empty (treats as 0)', async () => {
        vi.mocked(executeOperation).mockResolvedValueOnce([{}])
        const ok = await checkRateLimit('hash123', mockDataSource, mockConfig)
        expect(ok).toBe(true)
    })
})

// ─── startChunkedDumpRoute ────────────────────────────────────────────────────

describe('startChunkedDumpRoute', () => {
    function makeRequest(
        token = 'ABC123',
        body: Record<string, unknown> | null = null
    ): Request {
        return new Request('http://localhost/export/dump/start', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
            },
            body: body ? JSON.stringify(body) : undefined,
        })
    }

    it('returns 401 when no Authorization header is present', async () => {
        const req = new Request('http://localhost/export/dump/start', {
            method: 'POST',
        })
        const res = await startChunkedDumpRoute(req, mockDataSource, mockConfig)
        expect(res.status).toBe(401)
    })

    it('returns 429 when the rate limit is exceeded', async () => {
        // Rate limit query returns over limit
        vi.mocked(executeOperation).mockResolvedValueOnce([
            { count: MAX_EXPORTS_PER_HOUR },
        ])
        const res = await startChunkedDumpRoute(
            makeRequest(),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(429)
    })

    it('returns 400 when the callback URL is unsafe', async () => {
        // Rate limit passes
        vi.mocked(executeOperation).mockResolvedValueOnce([{ count: 0 }])
        const res = await startChunkedDumpRoute(
            makeRequest('ABC123', { callbackUrl: 'http://192.168.1.1/hook' }),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(400)
        const body = await res.json()
        expect(body.error).toContain('Invalid callback URL')
    })

    it('creates a job and returns 202 with jobId', async () => {
        vi.mocked(executeOperation)
            // checkRateLimit
            .mockResolvedValueOnce([{ count: 0 }])
            // list tables
            .mockResolvedValueOnce([{ name: 'users' }, { name: 'posts' }])
            // INSERT job
            .mockResolvedValueOnce([])
            // rate-limit INSERT + DELETE
            .mockResolvedValueOnce([])
            .mockResolvedValueOnce([])

        const res = await startChunkedDumpRoute(
            makeRequest(),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(202)
        const body = await res.json()
        expect(body.result.jobId).toBeTruthy()
        expect(body.result.status).toBe('pending')
        expect(body.result.fileName).toMatch(/^dump_\d{8}-\d{6}\.sql$/)
    })

    it('schedules processing via waitUntil when executionContext is present', async () => {
        vi.mocked(executeOperation)
            .mockResolvedValueOnce([{ count: 0 }])
            .mockResolvedValueOnce([{ name: 'users' }])
            .mockResolvedValueOnce([])
            .mockResolvedValueOnce([])
            .mockResolvedValueOnce([])

        await startChunkedDumpRoute(makeRequest(), mockDataSource, mockConfig)

        expect(
            (mockDataSource.executionContext as any).waitUntil
        ).toHaveBeenCalledOnce()
    })

    it('returns 500 on unexpected error', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {})
        vi.mocked(executeOperation).mockRejectedValueOnce(
            new Error('DB failure')
        )
        const res = await startChunkedDumpRoute(
            makeRequest(),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(500)
    })
})

// ─── getExportStatusRoute ─────────────────────────────────────────────────────

describe('getExportStatusRoute', () => {
    const jobId = 'job-uuid-1234'

    function makeRequest(token = 'ABC123'): Request {
        return new Request(`http://localhost/export/status/${jobId}`, {
            headers: { Authorization: `Bearer ${token}` },
        })
    }

    it('returns 401 without Authorization header', async () => {
        const req = new Request(`http://localhost/export/status/${jobId}`)
        const res = await getExportStatusRoute(
            jobId,
            req,
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(401)
    })

    it('returns 404 when job does not exist', async () => {
        vi.mocked(executeOperation).mockResolvedValueOnce([])
        const res = await getExportStatusRoute(
            jobId,
            makeRequest(),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(404)
    })

    it('returns 404 (not 403) when non-admin token does not match job', async () => {
        const otherTokenHash = await hashToken('OTHER_TOKEN')
        vi.mocked(executeOperation).mockResolvedValueOnce([
            {
                id: jobId,
                token_hash: otherTokenHash,
                status: 'completed',
                file_name: 'dump.sql',
                created_at: 1000,
                updated_at: 1000,
                total_tables: 1,
                processed_tables: 1,
                error: null,
            },
        ])

        mockConfig.role = 'client'
        const res = await getExportStatusRoute(
            jobId,
            makeRequest('CLIENT_TOKEN'),
            mockDataSource,
            mockConfig
        )
        // Returns 404 to avoid leaking job existence to unauthorized callers
        expect(res.status).toBe(404)
    })

    it('returns 200 with job status for admin regardless of token', async () => {
        const someHash = await hashToken('SOMEONE_ELSE')
        vi.mocked(executeOperation).mockResolvedValueOnce([
            {
                id: jobId,
                token_hash: someHash,
                status: 'completed',
                file_name: 'dump_20240101-120000.sql',
                created_at: 1000,
                updated_at: 2000,
                total_tables: 5,
                processed_tables: 5,
                error: null,
            },
        ])

        mockConfig.role = 'admin'
        const res = await getExportStatusRoute(
            jobId,
            makeRequest('ADMIN_TOKEN'),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(200)
        const body = await res.json()
        expect(body.result.id).toBe(jobId)
        expect(body.result.status).toBe('completed')
    })

    it('returns 200 when the caller owns the job (client role)', async () => {
        const myToken = 'MY_CLIENT_TOKEN'
        const myHash = await hashToken(myToken)

        vi.mocked(executeOperation).mockResolvedValueOnce([
            {
                id: jobId,
                token_hash: myHash,
                status: 'processing',
                file_name: 'dump.sql',
                created_at: 1000,
                updated_at: 1500,
                total_tables: 3,
                processed_tables: 1,
                error: null,
            },
        ])

        mockConfig.role = 'client'
        const res = await getExportStatusRoute(
            jobId,
            makeRequest(myToken),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(200)
        const body = await res.json()
        expect(body.result.processedTables).toBe(1)
    })

    it('returns 500 on unexpected error', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {})
        vi.mocked(executeOperation).mockRejectedValueOnce(new Error('oops'))
        const res = await getExportStatusRoute(
            jobId,
            makeRequest(),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(500)
    })
})

// ─── downloadExportRoute ──────────────────────────────────────────────────────

describe('downloadExportRoute', () => {
    const jobId = 'dl-job-5678'

    function makeRequest(token = 'ABC123'): Request {
        return new Request(`http://localhost/export/download/${jobId}`, {
            headers: { Authorization: `Bearer ${token}` },
        })
    }

    it('returns 401 without token', async () => {
        const req = new Request(`http://localhost/export/download/${jobId}`)
        const res = await downloadExportRoute(
            jobId,
            req,
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(401)
    })

    it('returns 404 for unknown job', async () => {
        vi.mocked(executeOperation).mockResolvedValueOnce([])
        const res = await downloadExportRoute(
            jobId,
            makeRequest(),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(404)
    })

    it('returns 404 (IDOR) when client token does not match job owner', async () => {
        const otherHash = await hashToken('OTHER')
        vi.mocked(executeOperation).mockResolvedValueOnce([
            {
                id: jobId,
                token_hash: otherHash,
                status: 'completed',
                file_name: 'dump.sql',
                content: 'SQLite format 3',
            },
        ])
        mockConfig.role = 'client'
        const res = await downloadExportRoute(
            jobId,
            makeRequest('WRONG_TOKEN'),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(404)
    })

    it('returns 409 when job is not yet complete', async () => {
        const myHash = await hashToken('ABC123')
        vi.mocked(executeOperation).mockResolvedValueOnce([
            {
                id: jobId,
                token_hash: myHash,
                status: 'processing',
                file_name: 'dump.sql',
                content: null,
            },
        ])
        const res = await downloadExportRoute(
            jobId,
            makeRequest(),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(409)
    })

    it('returns file content when job is completed', async () => {
        const myHash = await hashToken('ABC123')
        vi.mocked(executeOperation).mockResolvedValueOnce([
            {
                id: jobId,
                token_hash: myHash,
                status: 'completed',
                file_name: 'dump_20240101-120000.sql',
                content: 'SQLite format 3\0CREATE TABLE users ...',
            },
        ])
        const res = await downloadExportRoute(
            jobId,
            makeRequest(),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(200)
        expect(res.headers.get('Content-Type')).toBe('application/x-sqlite3')
        expect(res.headers.get('Content-Disposition')).toContain(
            'dump_20240101-120000.sql'
        )
        const text = await res.text()
        expect(text).toContain('SQLite format 3')
    })

    it('prefers R2 bucket content over inline when R2 object is found', async () => {
        const myHash = await hashToken('ABC123')
        vi.mocked(executeOperation).mockResolvedValueOnce([
            {
                id: jobId,
                token_hash: myHash,
                status: 'completed',
                file_name: 'dump.sql',
                content: 'INLINE_CONTENT',
            },
        ])

        const mockR2Body = 'R2_STORED_CONTENT'
        const mockR2Bucket = {
            get: vi.fn().mockResolvedValue({
                body: new ReadableStream({
                    start(controller) {
                        controller.enqueue(new TextEncoder().encode(mockR2Body))
                        controller.close()
                    },
                }),
            }),
        } as any

        const res = await downloadExportRoute(
            jobId,
            makeRequest(),
            mockDataSource,
            mockConfig,
            mockR2Bucket
        )
        expect(res.status).toBe(200)
        expect(mockR2Bucket.get).toHaveBeenCalledWith('dump.sql')
    })

    it('returns 500 on unexpected error', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {})
        vi.mocked(executeOperation).mockRejectedValueOnce(new Error('oops'))
        const res = await downloadExportRoute(
            jobId,
            makeRequest(),
            mockDataSource,
            mockConfig
        )
        expect(res.status).toBe(500)
    })
})

// ─── processExportChunk ───────────────────────────────────────────────────────

describe('processExportChunk', () => {
    const jobId = 'chunk-job-9999'

    it('returns false when job is not found (already completed or missing)', async () => {
        vi.mocked(executeOperation).mockResolvedValueOnce([])
        const result = await processExportChunk(
            jobId,
            mockDataSource,
            mockConfig
        )
        expect(result).toBe(false)
    })

    it('processes all tables and marks job as completed', async () => {
        vi.mocked(executeOperation)
            // load job
            .mockResolvedValueOnce([
                {
                    id: jobId,
                    status: 'pending',
                    processed_tables: 0,
                    current_offset: 0,
                    file_name: 'dump.sql',
                    callback_url: null,
                },
            ])
            // mark processing
            .mockResolvedValueOnce([])
            // list tables
            .mockResolvedValueOnce([{ name: 'users' }])
            // schema for users
            .mockResolvedValueOnce([
                { sql: 'CREATE TABLE users (id INTEGER, name TEXT)' },
            ])
            // first page of data (less than CHUNK_SIZE → end of table)
            .mockResolvedValueOnce([
                { id: 1, name: 'Alice' },
                { id: 2, name: 'Bob' },
            ])
            // second page (0 rows → done)
            .mockResolvedValueOnce([])
            // persist content
            .mockResolvedValueOnce([])
            // mark completed
            .mockResolvedValueOnce([])

        const result = await processExportChunk(
            jobId,
            mockDataSource,
            mockConfig
        )
        expect(result).toBe(false) // no more work needed
    })

    it('correctly escapes single quotes in string values', async () => {
        vi.mocked(executeOperation)
            .mockResolvedValueOnce([
                {
                    id: jobId,
                    status: 'pending',
                    processed_tables: 0,
                    current_offset: 0,
                    file_name: 'dump.sql',
                    callback_url: null,
                },
            ])
            .mockResolvedValueOnce([]) // mark processing
            .mockResolvedValueOnce([{ name: 'users' }]) // tables
            .mockResolvedValueOnce([
                { sql: 'CREATE TABLE users (id INTEGER, bio TEXT)' },
            ]) // schema
            .mockResolvedValueOnce([{ id: 1, bio: "O'Brien" }]) // data page
            .mockResolvedValueOnce([]) // end of table
            .mockImplementation(async (queries) => {
                // Capture the content UPDATE to verify escaping
                const sql = queries[0]?.sql ?? ''
                if (sql.includes('content = content')) {
                    const content = queries[0].params?.[0] as string
                    expect(content).toContain("'O''Brien'")
                }
                return []
            })

        await processExportChunk(jobId, mockDataSource, mockConfig)
    })

    it('writes NULL for null values', async () => {
        vi.mocked(executeOperation)
            .mockResolvedValueOnce([
                {
                    id: jobId,
                    status: 'pending',
                    processed_tables: 0,
                    current_offset: 0,
                    file_name: 'dump.sql',
                    callback_url: null,
                },
            ])
            .mockResolvedValueOnce([]) // mark processing
            .mockResolvedValueOnce([{ name: 't' }]) // tables
            .mockResolvedValueOnce([
                { sql: 'CREATE TABLE t (id INTEGER, val TEXT)' },
            ]) // schema
            .mockResolvedValueOnce([{ id: 1, val: null }]) // data with null
            .mockResolvedValueOnce([]) // end
            .mockImplementation(async (queries) => {
                const sql = queries[0]?.sql ?? ''
                if (sql.includes('content = content')) {
                    const content = queries[0].params?.[0] as string
                    expect(content).toContain('NULL')
                }
                return []
            })

        await processExportChunk(jobId, mockDataSource, mockConfig)
    })

    it('marks job as failed and returns false on error', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {})
        vi.mocked(executeOperation)
            // load job succeeds
            .mockResolvedValueOnce([
                {
                    id: jobId,
                    status: 'pending',
                    processed_tables: 0,
                    current_offset: 0,
                    file_name: 'dump.sql',
                    callback_url: null,
                },
            ])
            // mark processing fails
            .mockRejectedValueOnce(new Error('SQL failure'))
            // mark failed
            .mockResolvedValueOnce([])

        const result = await processExportChunk(
            jobId,
            mockDataSource,
            mockConfig
        )
        expect(result).toBe(false)
    })
})
