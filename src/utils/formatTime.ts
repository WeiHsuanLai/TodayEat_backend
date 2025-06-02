/**
 * 將 JWT 時間戳（秒）格式化為本地時間字串
 * @param timestamp 秒為單位的 Unix 時間戳（如 JWT 的 iat、exp）
 * @param options 時區與格式設定（預設使用當地時間）
 * @returns 格式化後的時間字串，或 undefined（如果未傳入 timestamp）
 */
export function formatUnixTimestamp(
    timestamp?: number,
    options?: {
        timeZone?: string;
        locale?: string;
        formatOptions?: Intl.DateTimeFormatOptions;
    }
): string | undefined {
    if (!timestamp) return undefined;

    const {
        timeZone,
        locale = 'zh-TW',
        formatOptions = {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        },
    } = options || {};

    return new Date(timestamp * 1000).toLocaleString(locale, {
        timeZone,
        ...formatOptions,
    });
}
