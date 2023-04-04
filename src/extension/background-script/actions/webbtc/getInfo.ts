import { MessageGetInfo } from "~/types";

const getInfo = async (message: MessageGetInfo) => {
  const supportedMethods = ["getInfo", "signPsbt"];

  return {
    data: {
      version: "Alby",
      supports: ["bitcoin"],
      methods: supportedMethods,
    },
  };
};

export default getInfo;
