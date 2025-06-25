// utils/mergeCustomWithDefault.ts
export function mergeCustomWithDefault(
    userItems: Map<string, string[]> | undefined,
    defaultItems: Map<string, string[]>
): Map<string, string[]> {
    const result = new Map<string, string[]>();

    // 先加入使用者自訂的項目（即使預設中沒有）
    if (userItems) {
        for (const [label, items] of userItems.entries()) {
            result.set(label, items);
        }
    }

    // 再補上預設中未被自訂的分類
    for (const [label, defaultList] of defaultItems.entries()) {
        if (!result.has(label)) {
            result.set(label, defaultList);
        }
    }

    return result;
}
