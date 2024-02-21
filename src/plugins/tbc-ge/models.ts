import { Account, Transaction } from '../../types/zenmoney'

export type OtpDevice = 'SMS_OTP' | 'TOKEN_GEMALTO' | 'TOKEN_VASCO'

export interface Signature {
  response: null
  status: string
  challenge: null
  regenerateChallengeCount: null
  authenticationAccessToken: null
  authenticationCode: null
  signer: null
  type: string
  authenticationCodeRsaPublicKey: null
  id: null
  otpId: string
}

export interface AccountOrDebitCard {
  id: number | null
  iban: string
  name: string
  description: string
  type: 'Card' | 'Saving'
  designUrl: string | null
  hasMultipleCards: boolean
  amount: number
  currency: string
}

export interface CardsAndAccounts {
  totalAmount: number
  totalAmountCurrency: string
  accountsAndDebitCards: AccountOrDebitCard[]
  creditCards: null
  childCards: null
  conversionFailed: boolean
}

export interface CardV2 {
  id: string
  blockedAmount: number
  numberSuffix: string
  isCardActivated: boolean
  expirationDate: number
  holderName: string
  userIsCardHolder: boolean
  backgroundImage: null
  designId: number
  designUrl: string
  harmAccessAllowedOnCard: boolean
  harmAccessOptionOnProduct: boolean
  isCardExpired: boolean
  isCardBlocked: boolean
  productId: number
}

export interface AccountV2 {
  id: number
  coreAccountId: number
  balance: number
  currency: string
  overdraftCheckDate: null
  overdraftAmount: null
}

export interface PreparedCardV2 {
  account: Account
  code: string // TODO GET from https://rmbgw.tbconline.ge/wallet/api/v1/cards
}

export interface PreparedAccountV2 {
  account: Account
}

/* {
  "cards": [{
  "cardId": 1004888841,
  "numberSuffix": "1234",
  "expiry": "05/25",
  "designId": 301,
  "friendlyName": "Card",
  "cardProvider": "Visa"
}]
} */

export interface CardProductV2 {
  iban: string
  friendlyName: null
  totalBalance: number
  currency: string
  primary: boolean
  operations: string[]
  canBePrimary: boolean
  isChildCard: boolean
  isCreditCard: boolean
  cardUsageType: number
  type: string
  typeText: string
  subType: string
  subTypeText: string
  hasPrefix: boolean
  cards: CardV2[]
  accounts: AccountV2[]
}

export interface LoginResponse {
  signatures: Signature[] | null
  signature: null
  validEmail: boolean
  success: boolean
  passcodeDirty: null
  secondPhaseRequired: boolean // 2FA
  accessToken: null
  changePasswordRequired: boolean
  changePasswordSuggested: boolean
  userSelectionRequired: boolean
  transactionId: string
  linkedProfiles: null
  possibleChallengeRegenTypes: string[]
  cookies: string[]
}

export interface PasswordLoginRequestV2 {
  'username': string
  'password': string
  'language': 'en'
  'deviceInfo': string
  'deviceData': string
  'deviceId': string
}

export interface EasyLoginRequestV2 {
  'userName': string
  'passcode': string
  'registrationId': string
  'deviceInfo': string
  'deviceData': string
  'passcodeType': string
  'language': 'en'
  'deviceId': string
  'trustedDeviceId'?: string // skip this to receive a sms code
}

export interface Device {
  androidId: string
  model: string
  manufacturer: string
  device: string
}

export class DeviceInfo {
  appVersion: string
  deviceId: string
  manufacturer: string
  modelNumber: string
  os: string
  remembered = true
  rooted = false

  constructor (appVersion: string, deviceId: string, manufacturer: string, modelNumber: string, os: string) {
    this.appVersion = appVersion
    this.deviceId = deviceId
    this.manufacturer = manufacturer
    this.modelNumber = modelNumber
    this.os = os
  }

  toBase64 (): string {
    return Buffer.from(JSON.stringify(this)).toString('base64')
  }
}

export class DeviceData extends DeviceInfo {
  isRemembered = 'true'
  isRooted = 'false'
  operatingSystem: string
  operatingSystemVersion: string

  static fromDeviceInfo (deviceInfo: DeviceInfo, operatingSystem: string, operatingSystemVersion: string): DeviceData {
    return new DeviceData(deviceInfo.appVersion, deviceInfo.deviceId, deviceInfo.manufacturer, deviceInfo.modelNumber, deviceInfo.os, operatingSystem, operatingSystemVersion)
  }

  constructor (appVersion: string, deviceId: string, manufacturer: string, modelNumber: string, os: string, operatingSystem: string,
    operatingSystemVersion: string) {
    super(appVersion, deviceId, manufacturer, modelNumber, os)
    this.operatingSystem = operatingSystem
    this.operatingSystemVersion = operatingSystemVersion
  }
}

export interface Auth {
  device: Device
  passcode: string
  registrationId: string
  trustedRegistrationId: string
}

export interface AuthV2 {
  username: string
  passcode: string
  registrationId: string
  trustedDeviceId?: string
}

export interface CertifyLoginResponseV2 {
  success: boolean
  signatures: null
  transactionId: null
  accessToken: null
  linkedProfiles: null
  changePasswordRequired: boolean
  changePasswordSuggested: boolean
  userSelectionRequired: boolean
  possibleChallengeRegenTypes: null
}

export interface Session {
  auth: Auth
  ibsAccessToken: string
}
export interface SessionV2 {
  cookies: string[]
  auth: AuthV2
}

export interface Preferences {
  login: string
  password: string
}

export interface FetchedAccountLoan {
  tag: 'account' | 'loan'
  product: unknown
}

export interface FetchedDeposit {
  tag: 'deposit'
  product: unknown
  depositProduct: unknown
  details: unknown
}

export type FetchedAccount = FetchedAccountLoan | FetchedDeposit

export interface FetchedAccountsV2{
  accounts: AccountOrDebitCard[]
}

export interface FetchedAccounts {
  accounts: FetchedAccount[]
  debitCardsWithBlockations: unknown[]
  creditCardsWithBlockations: unknown[]
  creditCards: unknown[]
}

export interface ConvertedCard {
  tag: 'card'
  coreAccountId: number
  account: Account
  holdTransactions: Transaction[]
}

export interface ConvertedCreditCard {
  tag: 'card'
  coreAccountId: number
  account: Account
  holdTransactions: Transaction[]
}

export interface ConvertedAccount {
  tag: 'account'
  coreAccountId: number
  account: Account
}

export interface ConvertedLoan {
  tag: 'loan'
  account: Account
}

export interface ConvertedDeposit {
  tag: 'deposit'
  depositId: number
  account: Account
}

export type ConvertedProduct = ConvertedAccount | ConvertedCard | ConvertedLoan | ConvertedDeposit | ConvertedCreditCard

export const APP_VERSION = '6.66.3'
export const OS_VERSION = '10'

export const PASSCODE = '12345'
