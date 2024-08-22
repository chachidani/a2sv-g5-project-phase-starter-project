import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQuery } from '../api/baseQuery';
import { TransactionResponseType } from '@/types/transaction.types';

const size = 1;

export const transactionApi = createApi({
  reducerPath: 'transactionApi',
  baseQuery: baseQuery(),
  endpoints: (builder) => ({
    getAllTransactions: builder.query<TransactionResponseType, string>({
      query: (page) => `/transactions?page=${page}&size=${size}`,
    }),
    getTransactionById: builder.query<void, string>({
      query: (id) => `/transactions/${id}`,
    }),
    getTransactionIncome: builder.query<void, string>({
      query: (page) => `/transactions/incomes?page=${page}&size=${size}`,
    }),
    getTransactionExpense: builder.query<void, string>({
      query: (page) => `/transactions/expense?page=${page}&size=${size}`,
    }),
    postDeposit: builder.mutation<
      void,
      { amount: number; description: string; type: string; receiverUserName: string }
    >({
      query: ({ amount, description, type, receiverUserName }) => ({
        url: '/transactions/deposit',
        method: 'POST',
        body: { amount, description, type, receiverUserName },
      }),
    }),
  }),
});

export const {
  useGetAllTransactionsQuery,
  useGetTransactionByIdQuery,
  useGetTransactionIncomeQuery,
  useGetTransactionExpenseQuery,
  usePostDepositMutation,
} = transactionApi;
