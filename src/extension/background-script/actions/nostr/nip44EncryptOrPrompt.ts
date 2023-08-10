import { USER_REJECTED_ERROR } from "~/common/constants";
import utils from "~/common/lib/utils";
import { getHostFromSender } from "~/common/utils/helpers";
import state from "~/extension/background-script/state";
import i18n from "~/i18n/i18nConfig";
import { Nip44MessageEncryptGet, PermissionMethodNostr, Sender } from "~/types";

import { addPermissionFor, hasPermissionFor } from "./helpers";

const nip44EncryptOrPrompt = async (
  message: Nip44MessageEncryptGet,
  sender: Sender
) => {
  const host = getHostFromSender(sender);
  if (!host) return;

  try {
    const hasPermission = await hasPermissionFor(
      PermissionMethodNostr["NOSTR_NIP44ENCRYPT"],
      host
    );

    if (hasPermission) {
      const response = (await state.getState().getNostr()).nip44Encrypt(
        message.args.peer,
        message.args.plaintext,
        message.args.v
      );

      return { data: response };
    } else {
      const promptResponse = await utils.openPrompt<{
        confirm: boolean;
        rememberPermission: boolean;
      }>({
        ...message,
        action: "public/nostr/confirm",
        args: {
          description: i18n.t("permissions:nostr.nip44encrypt"),
        },
      });

      // add permission to db only if user decided to always allow this request
      if (promptResponse.data.rememberPermission) {
        await addPermissionFor(
          PermissionMethodNostr["NOSTR_NIP44ENCRYPT"],
          host
        );
      }
      if (promptResponse.data.confirm) {
        const response = (await state.getState().getNostr()).nip44Encrypt(
          message.args.peer,
          message.args.plaintext,
          message.args.v
        );

        return { data: response };
      } else {
        return { error: USER_REJECTED_ERROR };
      }
    }
  } catch (e) {
    console.error("encrypt failed", e);
    if (e instanceof Error) {
      return { error: e.message };
    }
  }
};

export default nip44EncryptOrPrompt;
