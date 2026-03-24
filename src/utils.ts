import { corsHeaders } from './cors'

export type QueryTransactionRequest = {
    transaction?: QueryRequest[]
}

export type QueryRequest = {
    sql: string
    params?: any[]
}

export function createResponse(
    result: unknown,
    error: string | undefined,
    status: number
): Response {
    return new Response(JSON.stringify({ result, error }), {
        status,
        headers: {
            ...corsHeaders,
            'Content-Type': 'application/json',
        },
    })
}

/**
 * Quote a SQLite identifier (table or column name) using double-quote delimiters.
 * Any double-quote characters within the name are escaped by doubling them.
 * This prevents SQL injection when interpolating user-influenced identifiers.
 */
export function quoteIdentifier(name: string): string {
    return `"${name.replace(/"/g, '""')}"`
}

/**
 * Validate that a callback URL does not point to internal or private networks.
 * Blocks RFC-1918 private addresses, loopback, link-local, and cloud metadata
 * endpoints to prevent Server-Side Request Forgery (SSRF) attacks.
 */
export function isCallbackUrlSafe(urlString: string): boolean {
    let parsed: URL
    try {
        parsed = new URL(urlString)
    } catch {
        return false
    }

    // Only allow http and https schemes
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return false
    }

    const hostname = parsed.hostname.toLowerCase()

    // Block loopback addresses (IPv4, IPv6 with and without brackets)
    if (
        hostname === 'localhost' ||
        hostname === '127.0.0.1' ||
        hostname === '::1' ||
        hostname === '[::1]'
    ) {
        return false
    }

    // Block link-local APIPA / AWS-GCP metadata endpoint
    if (hostname === '169.254.169.254') {
        return false
    }

    // Block well-known cloud-internal metadata hostnames
    const blockedHostnames = [
        'metadata.google.internal',
        'instance-data',
        'metadata.internal',
    ]
    if (blockedHostnames.includes(hostname)) {
        return false
    }

    // Inspect raw IPv4 addresses and reject private/reserved ranges
    const ipv4Match = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
    if (ipv4Match) {
        const [, a, b] = ipv4Match.map(Number)
        if (a === 10) return false // 10.0.0.0/8
        if (a === 172 && b >= 16 && b <= 31) return false // 172.16.0.0/12
        if (a === 192 && b === 168) return false // 192.168.0.0/16
        if (a === 127) return false // 127.0.0.0/8
        if (a === 169 && b === 254) return false // 169.254.0.0/16 link-local
        if (a === 100 && b >= 64 && b <= 127) return false // 100.64.0.0/10 shared
        if (a === 0) return false // 0.0.0.0/8
    }

    return true
}
