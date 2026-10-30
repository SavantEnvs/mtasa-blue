// Fuzz harness: MTA XML layer (Shared/XML) over vendored tinyxml2. CXMLImpl::ParseString is what the
// server uses for XML received as a string; the harness then walks the wrapper tree and reads every
// attribute and typed tag content, and round-trips the tree through ToString() and a node copy.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "StdInc.h"

namespace
{
    constexpr int kMaxDepth = 64;

    void Walk(CXMLNode* node, int depth)
    {
        if (!node || depth > kMaxDepth)
            return;

        (void)node->GetTagName();
        (void)node->GetLine();
        (void)node->GetTagContent();
        (void)node->GetCommentText();
        bool         b = false;
        int          i = 0;
        unsigned int u = 0;
        float        f = 0;
        node->GetTagContent(b);
        node->GetTagContent(i);
        node->GetTagContent(u);
        node->GetTagContent(f);

        CXMLAttributes& attrs = node->GetAttributes();
        for (unsigned int a = 0; a < attrs.Count(); ++a)
        {
            CXMLAttribute* attr = attrs.Get(a);
            if (!attr)
                continue;
            (void)attr->GetName();
            (void)node->GetAttributeValue(attr->GetName());
            (void)attrs.Find(attr->GetName().c_str());
        }

        for (unsigned int c = 0; c < node->GetSubNodeCount(); ++c)
            Walk(node->GetSubNode(c), depth + 1);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > 64 * 1024)
        return -1;

    static CXMLImpl xml;
    std::string     text(reinterpret_cast<const char*>(data), size);

    std::unique_ptr<SXMLString> parsed = xml.ParseString(text.c_str());
    if (!parsed || !parsed->node)
        return 0;

    CXMLNode* root = parsed->node;
    Walk(root, 0);
    (void)root->ToString();

    if (CXMLNode* dummy = xml.CreateDummyNode())
    {
        root->CopyChildrenInto(dummy, true);
        (void)dummy->ToString();
        delete dummy;
    }
    return 0;
}
