// Fuzz harness: SharedUtil string / encoding helpers used on untrusted text (UTF-8 <-> UTF-16, escape
// and unescape, CArgMap "k=v&k=v" parsing, tea cipher, hex conversion, SString splitting and replacing).
// The first input byte selects the routine; the rest is the string it is given.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <SharedUtil.h>
#include <UTF8.h>

using namespace SharedUtil;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > 16 * 1024)
        return -1;

    const uint8_t which = data[0] % 9;
    const uint8_t* body = data + 1;
    const size_t   bsize = size - 1;
    const SString  text(std::string(reinterpret_cast<const char*>(body), bsize));

    switch (which)
    {
        case 0:
        {
            std::wstring wide = MbUTF8ToUTF16(text);
            std::string  back = UTF16ToMbUTF8(wide);
            (void)GetUTF8Confidence(body, static_cast<int>(bsize));
            (void)IsUTF8BOM(body, static_cast<uint>(bsize));
            (void)back;
            break;
        }
        case 1:
        {
            std::wstring wide = utf8_mbstowcs(text);
            std::string  back = utf8_wcstombs(wide);
            std::wstring wide2 = utf8_mbstowcs_orig(text);
            (void)utf8_wcstombs_orig(wide2);
            (void)back;
            break;
        }
        case 2:
        {
            SString escaped = EscapeString(text, "&=", '#');
            SString unescaped = UnescapeString(escaped, '#');
            if (unescaped != text)
                __builtin_trap();
            (void)UnescapeString(text, '#');
            (void)EscapeURLArgument(text);
            break;
        }
        case 3:
        {
            CArgMap map;
            map.SetFromString(text, true);
            SString out = map.ToString();
            CArgMap map2;
            map2.SetFromString(out, true);
            std::vector<SString> keys;
            map2.GetKeys(keys);
            for (const SString& key : keys)
            {
                (void)map2.Get(key);
                int v = 0;
                map2.Get(key, v);
            }
            map2.RemoveMultiValues();
            break;
        }
        case 4:
        {
            if (bsize < 1)
                break;
            size_t  keyLen = body[0] % (bsize);
            SString key(std::string(reinterpret_cast<const char*>(body + 1), keyLen > bsize - 1 ? bsize - 1 : keyLen));
            SString msg(std::string(reinterpret_cast<const char*>(body + 1 + key.length()), bsize - 1 - key.length()));
            SString decoded, encoded;
            TeaDecode(msg, key, &decoded);
            TeaEncode(msg, key, &encoded);
            SString roundtrip;
            TeaDecode(encoded, key, &roundtrip);
            break;
        }
        case 5:
        {
            SString hex = ConvertDataToHexString(body, static_cast<uint>(bsize));
            std::vector<unsigned char> back(bsize + 1);
            ConvertHexStringToData(hex, back.data(), static_cast<uint>(bsize));
            (void)GenerateSha256HexString(body, static_cast<uint>(bsize));
            break;
        }
        case 6:
        {
            std::vector<SString> parts;
            SString              delim(std::string(1, bsize ? static_cast<char>(body[0]) : ','));
            text.Split(delim, parts, 0, 0);
            SString left, right;
            text.Split(delim, &left, &right, 1);
            text.Split(delim, &left, &right, -1);
            (void)text.SplitLeft(delim, &right, 2);
            (void)text.SplitRight(delim, &left, 2);
            CSplitString split(text, delim);
            break;
        }
        case 7:
        {
            SString old(std::string(1, bsize && body[0] ? static_cast<char>(body[0]) : 'a'));
            (void)text.Replace(old, "xyz", false);
            (void)text.ReplaceI(old, "q", false);
            (void)text.ToUpper();
            (void)text.ToLower();
            (void)text.TrimStart(" \t");
            (void)text.TrimEnd(" \t");
            (void)text.ConformLineEndings();
            (void)text.Contains(old);
            (void)text.ContainsI(old);
            break;
        }
        case 8:
        {
            (void)IsValidVersionString(text);
            (void)ExtractVersionStringBuildNumber(text);
            (void)IsLuaCompiledScript(body, static_cast<uint>(bsize));
            (void)IsLuaObfuscatedScript(body, static_cast<uint>(bsize));
            (void)ConformResourcePath(text, true);
            break;
        }
    }
    return 0;
}
