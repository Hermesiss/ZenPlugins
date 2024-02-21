import { Account, ExtendedTransaction, ScrapeFunc } from '../../types/zenmoney'
import { fetchAccountsV2, fetchCardsV2, loginV2 } from './api'
import { convertAccountsV2, convertCardsV2 } from './converters'
import { AuthV2, Preferences } from './models'
import { adjustTransactions } from '../../common/transactionGroupHandler'

export const scrape: ScrapeFunc<Preferences> = async ({ preferences, fromDate, toDate }) => {
  ZenMoney.locale = 'en'
  toDate = toDate ?? new Date()
  const session = await loginV2(preferences, ZenMoney.getData('auth') as AuthV2 | undefined)
  console.log('session', session)
  console.log('session.auth', session.auth)
  ZenMoney.setData('auth', session.auth)
  ZenMoney.saveData()

  const accounts: Account[] = []
  const transactions: ExtendedTransaction[] = []
  await Promise.all(convertCardsV2(await fetchCardsV2(session)).map(async preparedCard => {
    const account = preparedCard.account
    accounts.push(account)
    if (ZenMoney.isAccountSkipped(account.id)) {
      console.log(`Account ${account.id} is skipped`)
    }

    // TODO add transactions

    /* if (account.tag === 'card') {
       transactions.push(...account.holdTransactions)
     }
     const apiTransactions = await fetchTransactions(account, fromDate, toDate!, session)
     for (const apiTransaction of apiTransactions) {
       const transaction = convertTransaction(apiTransaction, account)
       if (transaction != null) {
         transactions.push(transaction)
       }
     } */
  }))

  await Promise.all(convertAccountsV2(await fetchAccountsV2(session)).map(async preparedAccount => {
    const account = preparedAccount.account
    accounts.push(account)
    if (ZenMoney.isAccountSkipped(account.id)) {
      console.log(`Account ${account.id} is skipped`)
      return
    }
    console.log(`Fetching transactions for ${account.id}`)
    // TODO add transactions
  }))
  // TODO add deposits https://rmbgw.tbconline.ge/deposits/api/v1/deposits
  // TODO add loans https://rmbgw.tbconline.ge/loans/api/v1/list?ClientRoles=CoBorrower&ShowCards=false
  console.log('accounts', accounts)
  return {
    accounts,
    transactions: adjustTransactions({ transactions })
  }
}
