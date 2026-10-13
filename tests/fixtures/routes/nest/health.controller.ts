// @ts-nocheck fixture: framework packages are not installed
import { Controller, Get, Header } from '@nestjs/common'

@Controller({ path: 'health' })
export class HealthController {
  @Get('live')
  @Header('Cache-Control', 'no-store')
  live() {
    return 'ok'
  }
}
