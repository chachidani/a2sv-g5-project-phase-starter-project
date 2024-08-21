"use client";
import { useEffect } from "react";
import { useAppDispatch } from "@/app/Redux/store/store";
import { setCards, setStatus, setError } from "@/app/Redux/slices/cardSlice";
import CardService from "@/app/Services/api/CardService";

const useCardDispatch = (accessToken: string) => {
  const dispatch = useAppDispatch();

  useEffect(() => {
    const fetchInitialCards = async () => {
      try {
        dispatch(setStatus("loading"));
        const res: any = await CardService.getAllCards(accessToken);
        console.log(res.content, "myfggggggggggggggg");

        if (res) {
          dispatch(setCards(res.content));
          dispatch(setStatus("succeeded"));
        }
      } catch (error) {
        dispatch(setError("Failed to fetch cards"));
        dispatch(setStatus("failed"));
      }
    };

    fetchInitialCards();
  }, [dispatch, accessToken]);
};

export default useCardDispatch;
