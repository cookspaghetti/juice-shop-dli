/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import logger from './logger'

declare const module: { exports: { sqlAnalysisLogger?: SqlAnalysisTransport } }

interface SqlLogEvent {
  timestamp: string
  sqlText: string
}

class SqlAnalysisTransport {
  private queue: SqlLogEvent[] = []
  private isEnabled: boolean = false
  private apiUrl: string | null = null
  private maxQueueSize: number = 1000
  private logTimeoutMs: number = 3000
  private isSending: boolean = false

  constructor () {
    this.initialize()
  }

  private initialize (): void {
    this.apiUrl = 'https://cookspaghetti-sqli-classification-dli.hf.space/gradio_api/call/ingest-log'
    this.isEnabled = true
    logger.info(`SQL Analysis logger initialized with API endpoint: ${this.apiUrl}`)
  }

  public log (sqlText: string, duration?: number): void {
    logger.info(`SQL Command: ${sqlText}${duration ? ` (${duration}ms)` : ''}`)

    if (!this.isEnabled || !this.apiUrl) {
      return
    }

    const event: SqlLogEvent = {
      timestamp: new Date().toISOString(),
      sqlText
    }

    if (this.queue.length >= this.maxQueueSize) {
      this.queue.shift()
    }
    this.queue.push(event)

    this.drainQueue()
  }

  private drainQueue (): void {
    if (this.isSending || this.queue.length === 0 || !this.apiUrl) {
      return
    }

    this.isSending = true
    const event = this.queue.shift()

    if (!event) {
      this.isSending = false
      return
    }

    fetch(this.apiUrl, {
      method: 'POST',
      headers: this.buildHeaders(),
      body: JSON.stringify({ data: [event] }),
      signal: AbortSignal.timeout(this.logTimeoutMs)
    }).then(response => {
      if (!response.ok) {
        logger.warn(`SQL Analysis API returned status ${response.status} when logging query`)
      }
    }).catch((err: Error) => {
      if (err.name === 'AbortError') {
        logger.warn(`SQL Analysis API request timed out after ${this.logTimeoutMs}ms`)
      } else {
        logger.warn(`Failed to send SQL log to analysis API: ${err.message}`)
      }
    }).finally(() => {
      this.isSending = false
      if (this.queue.length > 0) {
        this.drainQueue()
      }
    })
  }

  private buildHeaders (): Record<string, string> {
    return {
      'Content-Type': 'application/json'
    }
  }

  public isOperational (): boolean {
    return this.isEnabled && this.apiUrl !== null
  }

  // Reinitialize state - primarily for testing
  public reinitialize (): void {
    this.queue = []
    this.isSending = false
    this.initialize()
  }

  // Test-only helper to flush queue
  public async flush (): Promise<void> {
    while (this.queue.length > 0 || this.isSending) {
      await new Promise(resolve => setTimeout(resolve, 50))
    }
  }
}

const sqlAnalysisLogger = new SqlAnalysisTransport()

module.exports = { sqlAnalysisLogger }
