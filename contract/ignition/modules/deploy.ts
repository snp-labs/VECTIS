import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { mock } from "../../test/mock";

export default buildModule("BccSNARK", (m) => {
  const bccSNARK = m.contract("BccSNARK", [mock.vk, mock.list_cm]);

  return { bccSNARK };
});