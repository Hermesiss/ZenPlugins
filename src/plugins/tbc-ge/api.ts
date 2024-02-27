import {
  APP_VERSION,
  AuthV2,
  DeviceData,
  DeviceInfo,
  LoginResponse,
  PASSCODE,
  Preferences,
  CardProductV2,
  SessionV2, CardsAndAccounts, TransactionsByDateV2, FetchHistoryV2Data
} from './models'
import {
  fetchApiDepositsV2,
  fetchApiLoansV2,
  fetchCardAndAccountsDashboardV2,
  fetchCardsListV2,
  fetchCertifyLoginBySmsV2,
  fetchConfirmTrustedDeviceV2,
  fetchGetSessionIdV2,
  fetchHistoryV2,
  fetchLoginByPasscodeV2,
  fetchLoginByPasswordV2,
  fetchRegisterDeviceV2,
  fetchTrustDeviceV2, fetchUnTrustDeviceV2
} from './fetchApi'
import { InvalidOtpCodeError } from '../../errors'

async function askOtpCodeV2 (prompt: string): Promise<string> {
  const sms = await ZenMoney.readLine(prompt,
    { inputType: 'number' })
  if (sms == null) {
    throw new InvalidOtpCodeError()
  }
  return sms.trim()
}

function generateDeviceInfo (): DeviceInfo {
  // replace all . with empty string
  const deviceId = ZenMoney.device.id.replace(/\./g, '_')
  return new DeviceInfo(APP_VERSION, deviceId, ZenMoney.device.manufacturer, ZenMoney.device.model, `${ZenMoney.device.os.name} ${ZenMoney.device.os.version}`)
}

function generateDeviceData (deviceInfo: DeviceInfo): DeviceData {
  return DeviceData.fromDeviceInfo(deviceInfo, ZenMoney.device.os.name, ZenMoney.device.os.version)
}

export async function loginV2 ({ login, password }: Preferences, auth?: AuthV2): Promise<SessionV2> {
  if (ZenMoney.trustCertificates != null && typeof (ZenMoney.trustCertificates) !== 'undefined') {
    ZenMoney.trustCertificates([
      `-----BEGIN CERTIFICATE-----
MIIGkTCCBXmgAwIBAgIJAM73sA/bbKMmMA0GCSqGSIb3DQEBCwUAMIG0MQswCQYD
VQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEa
MBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xLTArBgNVBAsTJGh0dHA6Ly9jZXJ0
cy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5LzEzMDEGA1UEAxMqR28gRGFkZHkgU2Vj
dXJlIENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTIzMDcyMzA5NDUxM1oX
DTI0MDgwODExMzgxMFowGTEXMBUGA1UEAwwOKi50YmNvbmxpbmUuZ2UwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZIn5vwmwskjEDsKckrldqi76fD1ns
wxvIsBTZ4jH6D6OStvXJeauD0Fp5qc4h17lRJ8fqBIhdDMy2QE3T4lMHncXhp/H+
UMyYFrhR8pxA6ZL+Ju26moqJB+JkV4nvzCQ/YetVIRUIhfsVYUt7KEkvGyP7fIvv
FmD5Td4vph9Oaf1bbBqMKN7gSbiSZtX2Ltufs4PPDakCs0FdCQUWM923Hm+akaqH
eZA/orqoZgH6jGaAvJii5OjeNA546ztAsiJ0Ot3RfdvHqERuOEJFVNn5dLVoukQE
2AmLgzpDZf66P6IKVVlE+rRmpq5L7lqksgbWyZ+zoBoGIPep9V8nK8MRAgMBAAGj
ggM+MIIDOjAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
BQcDAjAOBgNVHQ8BAf8EBAMCBaAwOAYDVR0fBDEwLzAtoCugKYYnaHR0cDovL2Ny
bC5nb2RhZGR5LmNvbS9nZGlnMnMxLTcxODUuY3JsMF0GA1UdIARWMFQwSAYLYIZI
AYb9bQEHFwEwOTA3BggrBgEFBQcCARYraHR0cDovL2NlcnRpZmljYXRlcy5nb2Rh
ZGR5LmNvbS9yZXBvc2l0b3J5LzAIBgZngQwBAgEwdgYIKwYBBQUHAQEEajBoMCQG
CCsGAQUFBzABhhhodHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wQAYIKwYBBQUHMAKG
NGh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS9nZGln
Mi5jcnQwHwYDVR0jBBgwFoAUQMK9J47MNIMwojPX+2yz8LQsgM4wJwYDVR0RBCAw
HoIOKi50YmNvbmxpbmUuZ2WCDHRiY29ubGluZS5nZTAdBgNVHQ4EFgQUvHA6FQ7m
t46DXh6kF914sJFSoAQwggF/BgorBgEEAdZ5AgQCBIIBbwSCAWsBaQB2AO7N0GTV
2xrOxVy3nbTNE6Iyh0Z8vOzew1FIWUZxH7WbAAABiYIjh7IAAAQDAEcwRQIgJsac
S/sITJJmGlN5a8xZY3YooiRDP8r6iIgwWWm1fdUCIQCigj3b6dwnBIqhLL/moajs
NeUmmVaIV4EhbsCwIiS75QB2AEiw42vapkc0D+VqAvqdMOscUgHLVt0sgdm7v6s5
2IRzAAABiYIjiIUAAAQDAEcwRQIgAXaGO+N0UJGBkiwu09PE6v3EPB160zEmaPeq
1NhVWGwCIQCRioar8aYdDTuYELM4u65s+W3M//hDjPkK3QDMDVN59AB3ANq2v2s/
tbYin5vCu1xr6HCRcWy7UYSFNL2kPTBI1/urAAABiYIjiOoAAAQDAEgwRgIhAJim
T+pePHzLnXo7tivqzSK9QcCiKOBRRbTIse7vP+MwAiEAxQf7eKJI+wNtQ+UUZ5U9
Jn9HSgZKJDiA8U3S87kzBQEwDQYJKoZIhvcNAQELBQADggEBAGrzJ+8cstmUxQKi
bDfrg/NKcf8Fxj+UxUB+W/kLWfnxtsJzVfCyxfqr0isF3IswXFYu2C/DYH+MJpKn
KQvLMpKmz23IRh6ksbWK5cWDhGUYf5tr9vU3W4hxn3nXL8Oq+mJd1X24kI+cl4bN
if/oa9jtmJBtq8EDPJG/iK0Pd0JCdKMMX3oDIHnZO7t5oLGC/m1qAHOl17/SIXx7
01ch/VYMG5NZi2A9/9NPESaza5PJmiKxDgHdmLR8HY+2jU94JSSGA2KX4TPf9nqR
WxdnLbK6zKx6+4WL9qWhGu6R+7HNPAaKOb7KXEwjV2ekr6FVZneKRFe/XivMk66O
7LluVHo=
-----END CERTIFICATE-----`,
      `-----BEGIN CERTIFICATE-----
MIIGkTCCBXmgAwIBAgIJAM73sA/bbKMmMA0GCSqGSIb3DQEBCwUAMIG0MQswCQYD
VQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEa
MBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xLTArBgNVBAsTJGh0dHA6Ly9jZXJ0
cy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5LzEzMDEGA1UEAxMqR28gRGFkZHkgU2Vj
dXJlIENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTIzMDcyMzA5NDUxM1oX
DTI0MDgwODExMzgxMFowGTEXMBUGA1UEAwwOKi50YmNvbmxpbmUuZ2UwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZIn5vwmwskjEDsKckrldqi76fD1ns
wxvIsBTZ4jH6D6OStvXJeauD0Fp5qc4h17lRJ8fqBIhdDMy2QE3T4lMHncXhp/H+
UMyYFrhR8pxA6ZL+Ju26moqJB+JkV4nvzCQ/YetVIRUIhfsVYUt7KEkvGyP7fIvv
FmD5Td4vph9Oaf1bbBqMKN7gSbiSZtX2Ltufs4PPDakCs0FdCQUWM923Hm+akaqH
eZA/orqoZgH6jGaAvJii5OjeNA546ztAsiJ0Ot3RfdvHqERuOEJFVNn5dLVoukQE
2AmLgzpDZf66P6IKVVlE+rRmpq5L7lqksgbWyZ+zoBoGIPep9V8nK8MRAgMBAAGj
ggM+MIIDOjAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
BQcDAjAOBgNVHQ8BAf8EBAMCBaAwOAYDVR0fBDEwLzAtoCugKYYnaHR0cDovL2Ny
bC5nb2RhZGR5LmNvbS9nZGlnMnMxLTcxODUuY3JsMF0GA1UdIARWMFQwSAYLYIZI
AYb9bQEHFwEwOTA3BggrBgEFBQcCARYraHR0cDovL2NlcnRpZmljYXRlcy5nb2Rh
ZGR5LmNvbS9yZXBvc2l0b3J5LzAIBgZngQwBAgEwdgYIKwYBBQUHAQEEajBoMCQG
CCsGAQUFBzABhhhodHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wQAYIKwYBBQUHMAKG
NGh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS9nZGln
Mi5jcnQwHwYDVR0jBBgwFoAUQMK9J47MNIMwojPX+2yz8LQsgM4wJwYDVR0RBCAw
HoIOKi50YmNvbmxpbmUuZ2WCDHRiY29ubGluZS5nZTAdBgNVHQ4EFgQUvHA6FQ7m
t46DXh6kF914sJFSoAQwggF/BgorBgEEAdZ5AgQCBIIBbwSCAWsBaQB2AO7N0GTV
2xrOxVy3nbTNE6Iyh0Z8vOzew1FIWUZxH7WbAAABiYIjh7IAAAQDAEcwRQIgJsac
S/sITJJmGlN5a8xZY3YooiRDP8r6iIgwWWm1fdUCIQCigj3b6dwnBIqhLL/moajs
NeUmmVaIV4EhbsCwIiS75QB2AEiw42vapkc0D+VqAvqdMOscUgHLVt0sgdm7v6s5
2IRzAAABiYIjiIUAAAQDAEcwRQIgAXaGO+N0UJGBkiwu09PE6v3EPB160zEmaPeq
1NhVWGwCIQCRioar8aYdDTuYELM4u65s+W3M//hDjPkK3QDMDVN59AB3ANq2v2s/
tbYin5vCu1xr6HCRcWy7UYSFNL2kPTBI1/urAAABiYIjiOoAAAQDAEgwRgIhAJim
T+pePHzLnXo7tivqzSK9QcCiKOBRRbTIse7vP+MwAiEAxQf7eKJI+wNtQ+UUZ5U9
Jn9HSgZKJDiA8U3S87kzBQEwDQYJKoZIhvcNAQELBQADggEBAGrzJ+8cstmUxQKi
bDfrg/NKcf8Fxj+UxUB+W/kLWfnxtsJzVfCyxfqr0isF3IswXFYu2C/DYH+MJpKn
KQvLMpKmz23IRh6ksbWK5cWDhGUYf5tr9vU3W4hxn3nXL8Oq+mJd1X24kI+cl4bN
if/oa9jtmJBtq8EDPJG/iK0Pd0JCdKMMX3oDIHnZO7t5oLGC/m1qAHOl17/SIXx7
01ch/VYMG5NZi2A9/9NPESaza5PJmiKxDgHdmLR8HY+2jU94JSSGA2KX4TPf9nqR
WxdnLbK6zKx6+4WL9qWhGu6R+7HNPAaKOb7KXEwjV2ekr6FVZneKRFe/XivMk66O
7LluVHo=
-----END CERTIFICATE-----`
    ])
  }
  let session: SessionV2
  let cookies
  let deviceTrusted = false
  let loginInfo: LoginResponse
  const deviceInfo = generateDeviceInfo()
  const deviceData = generateDeviceData(deviceInfo)
  if (auth == null) {
    loginInfo = await fetchLoginByPasswordV2({ username: login, password, deviceInfo, deviceData })
    if (loginInfo.secondPhaseRequired) {
      cookies = await fetchCertifyLoginBySmsV2(await askOtpCodeV2('Enter the code from SMS'), loginInfo.transactionId)
    } else {
      deviceTrusted = true
      cookies = loginInfo.cookies
    }
    const registrationId = await fetchRegisterDeviceV2({ deviceName: deviceInfo.manufacturer, passcode: PASSCODE, deviceId: deviceInfo.deviceId })
    session = {
      cookies,
      auth: {
        username: login,
        passcode: PASSCODE,
        registrationId
      }
    }
  } else {
    loginInfo = await fetchLoginByPasscodeV2(auth, deviceInfo, deviceData)
    if (loginInfo.secondPhaseRequired) {
      cookies = await fetchCertifyLoginBySmsV2(await askOtpCodeV2('Enter the code from SMS'), loginInfo.transactionId)
    } else {
      deviceTrusted = true
      cookies = loginInfo.cookies
    }
    session = {
      cookies,
      auth
    }
  }
  const sessionId = await fetchGetSessionIdV2(cookies)
  if (!deviceTrusted) {
    let orderId = await fetchTrustDeviceV2(deviceData, sessionId, cookies)
    let code = await askOtpCodeV2('Enter the second code from SMS for trusting the device')
    let trustId: string | null = null

    trustId = await fetchConfirmTrustedDeviceV2(code, orderId, cookies)
    if (trustId == null) {
      await ZenMoney.alert('Device was already trusted, but we don\'t have the trustedDeviceId. We need to untrust the device and trust it again')
      await fetchUnTrustDeviceV2(deviceData, sessionId, cookies)
      orderId = await fetchTrustDeviceV2(deviceData, sessionId, cookies)
      code = await askOtpCodeV2('Enter the last code from SMS for trusting the device again')
      trustId = await fetchConfirmTrustedDeviceV2(code, orderId, cookies)
    }

    if (trustId == null) {
      throw new InvalidOtpCodeError('Device trust failed')
    }

    session.auth.trustedDeviceId = trustId
  }

  return session
}

export async function fetchDepositsV2 (session: SessionV2): Promise<unknown> {
  return await fetchApiDepositsV2(session)
}

export async function fetchLoansV2 (session: SessionV2): Promise<unknown> {
  return await fetchApiLoansV2(session)
}

export async function fetchTransactionsV2 (session: SessionV2, fromDate: Date, data: FetchHistoryV2Data): Promise<TransactionsByDateV2[]> {
  return await fetchHistoryV2(session, fromDate, data)
}

export async function fetchCardsV2 (session: SessionV2): Promise<CardProductV2[]> {
  return await fetchCardsListV2(session)
}

export async function fetchAccountsV2 (session: SessionV2): Promise<CardsAndAccounts> {
  return await fetchCardAndAccountsDashboardV2(session)
}
