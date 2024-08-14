"use client";
import React from "react";
import { useForm } from "react-hook-form";
import Link from "next/link";
import {
  AtSymbolIcon,
  KeyIcon,
  ExclamationCircleIcon,
  ArrowPathIcon,
} from "@heroicons/react/24/outline";
const LoginForm: React.FC = () => {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm();

  const onSubmit = (data: any) => {
    console.log(data);
  };
    const isLoading = false; // Set this to true if the component is loading

  return (
    <div className="flex items-center justify-center   h-[50vh]">
      <div className="flex-col items-center justify-center  h-24  w-[50vh] ">
        <form onSubmit={handleSubmit(onSubmit)} className=" p-4 rounded-2xl ">
          <div className="flex  flex-col justify-center items-center my-4 ">
            <img
              src="https://cdn.freelogovectors.net/wp-content/uploads/2024/03/chase_logo-freelogovectors.net_.png"
              alt="next logo"
                className="h-30 w-40 m-auto my-4"
            />
            <h1 className=" font-bold text-4xl text-gray-700 font-serif ">NEXT BANK</h1>
          </div>

          <div className="my-10">
            <div>
              <label
                htmlFor="username"
                className="block font-bold mb-2 text-gray-700"
              >
                Username
              </label>
              <input
                id="username"
                type="text"
                placeholder="Username"
                {...register("username", { required: "Username is required" })}
                className="w-full m-auto border-gray-200 border-2  rounded-lg shadow-sm focus:border-indigo-500 focus:ring-indigo-500 h-14 px-2.5 "
              />
              {errors.username && (
                <div className="flex gap-1">
                  <ExclamationCircleIcon className="h-5 w-5 text-red-500" />
                  <p className="text-red-500">
                    {errors.username.message as string}
                  </p>
                </div>
              )}
            </div>
          </div>
          <div className="my-10">
            <div>
              <label
                htmlFor="password"
                className="block font-bold mb-2 text-gray-700"
              >
                Password
              </label>
              <input
                id="password"
                type="password"
                placeholder="Password"
                {...register("password", { required: "Password is required" })}
                className="w-full m-auto border-gray-200 border-2  rounded-lg shadow-sm focus:border-indigo-500 focus:ring-indigo-500 h-14 px-2.5"
              />
              {errors.password && (
                <div className="flex gap-1">
                  <ExclamationCircleIcon className="h-5 w-5 text-red-500" />
                  <p className="text-red-500">
                    {errors.password.message as string}
                  </p>
                </div>
              )}
            </div>
          </div>
          <button
            type="submit"
            className="bg-blue-500 text-white px-4 py-2 mt-4 w-full rounded-3xl text-xl"
          >
            {isLoading ? (
              <ArrowPathIcon className="h-5 w-5 animate-spin mr-2 text-white" />
            ) : (
              "Login"
            )}
          </button>

          <div className="my-14 flex flex-col items-center text-xl">
            <p>
              Don't have an account?{" "}
              <span className="text-indigo-500 font-medium text-xl">
                <Link href="/signup">Sign Up</Link>
              </span>
            </p>
            <p className="my-8 text-indigo-500 font-medium">
              <Link href="/forgotpassword">Forgot password?</Link>
            </p>
          </div>
        </form>
      </div>
    </div>
  );
};

export default LoginForm;
