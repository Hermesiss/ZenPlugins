import { Account, ExtendedTransaction, ScrapeFunc } from '../../types/zenmoney'
import { fetchAccountsV2, fetchCardsV2, fetchTransactionsV2, loginV2 } from './api'
import { convertAccountsV2, convertCardsV2, convertTransactionsV2 } from './converters'
import { AuthV2, FetchHistoryV2Data, Preferences } from './models'
import { adjustTransactions } from '../../common/transactionGroupHandler'

export const scrape: ScrapeFunc<Preferences> = async ({ preferences, fromDate, toDate }) => {
  ZenMoney.locale = 'en'
  const session = await loginV2(preferences, ZenMoney.getData('auth') as AuthV2 | undefined)
  ZenMoney.setData('auth', session.auth)
  ZenMoney.saveData()

  const accounts: Account[] = []
  const transactions: ExtendedTransaction[] = []
  const fetchHistoryV2Data: FetchHistoryV2Data[] = []
  const accountToSyncIds = new Map<string, string[]>()
  await Promise.all(convertCardsV2(await fetchCardsV2(session)).map(async preparedCard => {
    const account = preparedCard.account

    if (ZenMoney.isAccountSkipped(account.id)) {
      console.log(`Account ${account.id} is skipped`)
      return
    }
    accounts.push(account)
    fetchHistoryV2Data.push({
      account,
      currency: account.instrument,
      iban: preparedCard.iban,
      id: preparedCard.id.toString()
    })
  }))

  await Promise.all(convertAccountsV2(await fetchAccountsV2(session)).map(async preparedAccount => {
    const account = preparedAccount.account
    if (ZenMoney.isAccountSkipped(account.id)) {
      console.log(`Account ${account.id} is skipped`)
      return
    }
    accounts.push(account)
    fetchHistoryV2Data.push({
      account,
      currency: account.instrument,
      iban: preparedAccount.iban,
      id: preparedAccount.account.id
    })
  }))
  // TODO add deposits https://rmbgw.tbconline.ge/deposits/api/v1/deposits
  // TODO add loans https://rmbgw.tbconline.ge/loans/api/v1/list?ClientRoles=CoBorrower&ShowCards=false

  for (const account of accounts) {
    accountToSyncIds.set(account.id, [account.id])
  }

  for (const data of fetchHistoryV2Data) {
    const tr = await fetchTransactionsV2(session, fromDate, data)
    const t = convertTransactionsV2(tr, data)
    transactions.push(...t)
  }

  console.log(transactions)
  return {
    accounts,
    transactions: adjustTransactions({ transactions })
  }
}
