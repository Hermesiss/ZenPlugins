import { FetchResponse } from '../../common/network'

export function getCookies (response: FetchResponse): string[] {
  const headers = response.headers as Record<string, unknown>
  const cookies = headers['set-cookie'] as string
  return cookies.split(';,')
}
