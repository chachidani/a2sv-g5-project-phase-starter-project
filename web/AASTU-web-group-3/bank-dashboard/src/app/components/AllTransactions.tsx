import React from "react";
import { FaRegArrowAltCircleUp, FaRegArrowAltCircleDown } from "react-icons/fa";

const transactions = [
    {
      transactionId: "TXN001",
      transactionDescription: "Mobile Service",
      type: "Service",
      card: "1234-5678-9012",
      date: "2024-08-01T14:35:00",
      amount: 29.99,
      receipt: "RCP001",
    },
    {
      transactionId: "TXN002",
      transactionDescription: "Spotify Subscription",
      type: "Service",
      card: "2345-6789-0123",
      date: "2024-08-03T09:15:00", 
      amount: -9.99,
      receipt: "RCP002",
    },
    {
      transactionId: "TXN003",
      transactionDescription: "Amazon Shopping",
      type: "Shopping",
      card: "3456-7890-1234",
      date: "2024-08-05T19:45:00", 
      amount: 59.95,
      receipt: "RCP003",
    },
    {
      transactionId: "TXN004",
      transactionDescription: "Grocery Shopping",
      type: "Shopping",
      card: "4567-8901-2345",
      date: "2024-08-07T11:20:00", 
      amount: -105.75,
      receipt: "RCP004",
    },
    {
      transactionId: "TXN005",
      transactionDescription: "Bank Transfer",
      type: "Transfer",
      card: "5678-9012-3456",
      date: "2024-08-10T16:05:00", 
      amount: +200.0,
      receipt: "RCP005",
    },
    {
      transactionId: "TXN006",
      transactionDescription: "Mobile Service",
      type: "Service",
      card: "6789-0123-4567",
      date: "2024-08-12T08:30:00", 
      amount: -29.99,
      receipt: "RCP006",
    },
    {
      transactionId: "TXN007",
      transactionDescription: "Spotify Subscription",
      type: "Service",
      card: "7890-1234-5678",
      date: "2024-08-15T22:10:00",
      amount: -9.99,
      receipt: "RCP007",
    },
  ];



  const formatDate = (dateString:string) => {
    const date = new Date(dateString)
  

    const formattedDate = date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
    })

    const formattedTime = date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: true,
    })
  
    return `${formattedDate}, ${formattedTime}`
  }
  

const AllTransactions = () => {
  return (
    <div className="">
      
  <h1 className="m-2 text-xl font-semibold"> Recent Transaction </h1>        
    <section className="border-0 rounded-xl bg-white shadow-md mx-2 p-2">
      <div className="hidden lg:grid grid-cols-7 font-medium text-sky-300 text-xs h-7 items-center border-b mt-2">
        <div>Description</div>
        <div>Transaction Id</div>
        <div>Type</div>
        <div>Card</div>
        <div>Date</div>
        <div>Amount</div>
        <div className="justify-self-center">Receipt</div>
      </div>
 

      {transactions.map((transaction, index) => (
        <div
          key={index}
          className="grid grid-cols-7  border-b min-h-12 items-center text-xs lg:font-medium "
        >
          <div className="flex items-center gap-2 col-span-5 lg:col-span-1 lg:font-medium">
            {transaction.amount < 0 ? (
              <FaRegArrowAltCircleUp
                color="#718EBF"
                className="text-4xl
              md:text-xl
              xl:text-3xl"
              />
            ) : (
              <FaRegArrowAltCircleDown
                color="#718EBF"
                className="text-4xl
                md:text-xl
                xl:text-3xl"
              />
            )}
            <span>{transaction.transactionDescription}</span>
          </div>
          <div className="hidden lg:block">{transaction.transactionId}</div>
          <div className="hidden lg:block">{transaction.type}</div>
          <div className="hidden lg:block">{transaction.card}</div>
          <div className="hidden lg:block">{formatDate(transaction.date)}</div>
          <div className={`col-span-2 lg:col-span-1 justify-self-end lg:justify-self-auto
                ${transaction.amount<0?"text-red-500":"text-green-500"}
            `} >{transaction.amount<0?"-":"+"}${Math.abs(transaction.amount)}</div>
          <div className="hidden lg:block border p-1 rounded-lg w-auto justify-self-center hover:border-">Download</div>
        </div>
      ))}
    </section>
    </div>
  );
};

export default AllTransactions;
