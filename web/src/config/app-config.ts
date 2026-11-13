import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "ARTEX-Pro",
  imageName: process.env.NEXT_PUBLIC_ARTEX_IMAGE_NAME || "artex-pro",
  version: packageJson.version,
  copyright: `© ${currentYear}, ARTEX-Pro.`,
  meta: {
    title: "ARTEX-Pro — 自主渗透测试控制台",
    description: "LLM 驱动的自主渗透测试系统控制台",
  },
};
