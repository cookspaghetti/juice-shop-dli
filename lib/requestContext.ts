/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { AsyncLocalStorage } from 'node:async_hooks'
import type { Request, Response, NextFunction } from 'express'

interface RequestContext {
  isUserRequest: boolean
}

export const requestContext = new AsyncLocalStorage<RequestContext>()

export function requestContextMiddleware (req: Request, res: Response, next: NextFunction): void {
  requestContext.run({ isUserRequest: true }, next)
}
