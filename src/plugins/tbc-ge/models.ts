import { Account, AccountOrCard, AccountType, Movement, Transaction } from '../../types/zenmoney'

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

export interface FetchHistoryV2Data {
  account: Account
  currency: string
  iban: string
  id: string
}

export interface TransactionRecordV2 {
  transactionId: number
  accountId: number
  entryType: 'StandardMovement' | 'BlockedTransaction'
  movementId: string
  transactionDate: null | string
  localTime: null | string
  repeatTransaction: null | boolean
  setAutomaticTransfer: null | boolean
  payback: null | boolean
  saveAsTemplate: null | boolean
  shareReceipt: null | boolean
  dispute: null | boolean
  title: string
  subTitle: string
  amount: number
  currency: string
  categoryCode: string
  subCategoryCode: string
  isSplit: null | boolean
  transactionSubtype: number
  blockedMovementDate: null | string
  blockedMovementCardId: null | number
  blockedMovementIban: null | string
  transactionStatus: string
  isDebit: boolean
}

export interface TransactionsByDateV2 {
  date: number
  transactions: TransactionRecordV2[]
}

export interface PreparedCardV2 {
  account: AccountOrCard
  code: string // TODO GET from https://rmbgw.tbconline.ge/wallet/api/v1/cards
  id: number
  iban: string
}

export interface PreparedAccountV2 {
  account: AccountOrCard
  iban: string
}

export interface CoreAccountId {
  currency: string
  iban: string
  id: string
  type: number
}

export interface TransactionV2 {
  coreAccountIds: CoreAccountId[]
  isChildCardRequest: boolean
  pageType: string
  showBlockedTransactions: boolean
}

export class TransactionBlockedV2 {
  transaction: TransactionRecordV2
  amount: number
  merchant: string
  city: string
  countryCode: string

  isCash (): boolean {
    return this.transaction.title.includes('ATM ') // TODO add cash in
  }

  constructor (transaction: TransactionRecordV2) {
    if (transaction.entryType !== 'BlockedTransaction') {
      throw new Error('Invalid transaction entryType, expected BlockedTransaction')
    }
    this.transaction = transaction
    this.amount = transaction.amount
    const arr = transaction.title.split('>')
    this.merchant = arr[0].trim()
    const arr2 = arr[1].split(' ')
    this.city = arr2[0].trim()
    this.countryCode = arr2[1].trim()
  }
}

export class TransactionTransferV2 {
  transaction: TransactionRecordV2
  amount: number

  public get isIncome (): boolean {
    return this.transaction.categoryCode === 'INCOME'
  }

  constructor (transaction: TransactionRecordV2) {
    if (!TransactionTransferV2.isTransfer(transaction)) {
      throw new Error('Invalid transaction categoryCode')
    }
    this.transaction = transaction
    this.amount = transaction.amount
  }

  static isTransfer (transaction: TransactionRecordV2): boolean {
    return transaction.entryType === 'StandardMovement' &&
      (transaction.categoryCode === 'INCOME' || transaction.categoryCode === 'PAYMENTS' || transaction.categoryCode === 'BANK_INSURE_TAX')
  }
}

export class TransactionStandardMovementV2 {
  transaction: TransactionRecordV2
  merchant: string
  amount: number
  date: Date
  cardNum: string
  mcc: number

  isCash (): boolean {
    return this.transaction.categoryCode === 'CASHOUT' // TODO add cash in
  }

  constructor (transaction: TransactionRecordV2) {
    if (transaction.entryType !== 'StandardMovement') {
      throw new Error('Invalid transaction entryType, expected StandardMovement')
    }
    if (TransactionTransferV2.isTransfer(transaction)) {
      throw new Error('Invalid transaction categoryCode')
    }
    this.transaction = transaction
    const arr = transaction.title.split(',')
    this.merchant = arr[0].split('-')[1].trim()
    this.amount = transaction.amount
    this.date = new Date(arr[2])
    this.cardNum = arr[arr.length - 1].trim().slice(-4)
    this.mcc = Number.parseInt(arr[arr.length - 3].replace('MCC:', '').trim())
  }
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

export interface FetchedAccountsV2 {
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

export const COMPANY_ID = '15622'

export const createCashMovement = (currency: string, sum: number): Movement => {
  return {
    account: {
      company: null,
      instrument: currency,
      syncIds: null,
      type: AccountType.cash
    },
    fee: 0,
    id: null,
    invoice: null,
    sum
  }
}
