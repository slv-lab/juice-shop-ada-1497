/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true

      // SSRF protection: Only allow requests to safe image host domains
      const allowedHosts = ['imgur.com', 'images.example.com'] // Add your trusted domains here
      let parsedUrl
      try {
        parsedUrl = new URL(url)
      } catch(e) {
        return next(new Error('Invalid image URL provided'))
      }
      // SSRF strict hostname and port check
      function isAllowedHost(hostname: string, port: string | null, protocol: string, allowedHosts: string[]): boolean {
        // Matches exactly one of the allowed hosts (prevent subdomain/typo attempts) and default port only
        // imgur.com and images.example.com only, *no* subdomains, *no* custom port
        const defaultPort = protocol === 'https:' ? '443' : protocol === 'http:' ? '80' : ''
        return allowedHosts.some(allowed =>
          hostname === allowed &&
          (port === '' || port === null || port === defaultPort)
        )
      }
      const isAllowed =
        (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') &&
        isAllowedHost(parsedUrl.hostname, parsedUrl.port, parsedUrl.protocol, allowedHosts)
      if (!isAllowed) {
        return next(new Error('Image URL points to an unallowed host'))
      }

      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
