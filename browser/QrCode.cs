using System;
using System.Collections.Generic;
using System.Text;

namespace Recognition.Browser
{
    // A small QR code encoder: byte mode, error correction level M, versions 1 to 10 (up to 213 bytes). Pure code: no network, no files.
    // Written for the "session exported" page, where the QR carries the packet's fingerprint so it can be read on a phone or compared on
    // another device. It is a line-by-line port of a reference implementation that was checked two ways: the codeword stream matches
    // OpenCV's independent encoder for 155 different texts, and the symbols decode with two different OpenCV decoders. The tests compare
    // fixed texts against the reference matrices by hash.
    internal static class QrCode
    {
        private static readonly int[] EccPerBlock = { -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26 };
        private static readonly int[] NumBlocks = { -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5 };
        public const int MaxBytes = 213;

        // Returns the modules (true = dark) as a size x size grid, or throws ArgumentException when the text is too long.
        public static bool[,] Encode(string text, out int version, out int mask)
        {
            var data = Encoding.UTF8.GetBytes(text ?? "");
            int ver = 0;
            for (int v = 1; v <= 10; v++)
            {
                int capBits = DataCodewords(v) * 8;
                int need = 4 + (v < 10 ? 8 : 16) + data.Length * 8;
                if (need <= capBits) { ver = v; break; }
            }
            if (ver == 0) throw new ArgumentException("text too long for the QR code (max " + MaxBytes + " bytes)");

            var bits = new List<int>();
            void Put(int val, int n) { for (int i = n - 1; i >= 0; i--) bits.Add((val >> i) & 1); }
            Put(0b0100, 4); Put(data.Length, ver < 10 ? 8 : 16);
            foreach (var b in data) Put(b, 8);
            int cap = DataCodewords(ver) * 8;
            Put(0, Math.Min(4, cap - bits.Count));
            Put(0, ((8 - bits.Count % 8) % 8));
            int pad = 0xEC;
            while (bits.Count < cap) { Put(pad, 8); pad ^= 0xEC ^ 0x11; }
            var cw = new int[bits.Count / 8];
            for (int i = 0; i < cw.Length; i++) { int s = 0; for (int j = 0; j < 8; j++) s |= bits[i * 8 + j] << (7 - j); cw[i] = s; }

            // error correction and interleaving
            int nb = NumBlocks[ver], ecl = EccPerBlock[ver], raw = RawModules(ver) / 8;
            int nshort = nb - raw % nb, shortlen = raw / nb;
            var blocks = new List<int[]>(); var div = RsDivisor(ecl); int k = 0;
            for (int i = 0; i < nb; i++)
            {
                int dl = shortlen - ecl + (i < nshort ? 0 : 1);
                var d = new int[dl]; Array.Copy(cw, k, d, 0, dl); k += dl;
                var e = RsRemainder(d, div);
                int padLen = i < nshort ? dl + 1 : dl;     // short blocks get one placeholder so the columns line up
                var blk = new int[padLen + ecl];
                Array.Copy(d, 0, blk, 0, dl);
                Array.Copy(e, 0, blk, padLen, ecl);
                blocks.Add(blk);
            }
            var outCw = new List<int>();
            for (int i = 0; i < blocks[0].Length; i++)
                for (int j = 0; j < blocks.Count; j++)
                    if (i != shortlen - ecl || j >= nshort) outCw.Add(blocks[j][i]);

            int size = ver * 4 + 17;
            var mod = new bool[size, size]; var fn = new bool[size, size];
            void SetF(int x, int y, bool dark) { mod[y, x] = dark; fn[y, x] = true; }

            for (int i = 0; i < size; i++) { SetF(6, i, i % 2 == 0); SetF(i, 6, i % 2 == 0); }
            void Finder(int cx, int cy)
            {
                for (int dy = -4; dy <= 4; dy++)
                    for (int dx = -4; dx <= 4; dx++)
                    {
                        int dist = Math.Max(Math.Abs(dx), Math.Abs(dy)), xx = cx + dx, yy = cy + dy;
                        if (xx >= 0 && xx < size && yy >= 0 && yy < size) SetF(xx, yy, dist != 2 && dist != 4);
                    }
            }
            Finder(3, 3); Finder(size - 4, 3); Finder(3, size - 4);
            var ap = AlignPositions(ver); int n = ap.Count;
            for (int i = 0; i < n; i++)
                for (int j = 0; j < n; j++)
                {
                    if ((i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0)) continue;
                    for (int dy = -2; dy <= 2; dy++)
                        for (int dx = -2; dx <= 2; dx++)
                            SetF(ap[i] + dx, ap[j] + dy, Math.Max(Math.Abs(dx), Math.Abs(dy)) != 1);
                }

            void DrawFormat(int m)
            {
                int dataF = (0 << 3) | m;                       // error correction level M is 00
                int rem = dataF;
                for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
                int fb = ((dataF << 10) | rem) ^ 0x5412;
                for (int i = 0; i < 6; i++) SetF(8, i, ((fb >> i) & 1) == 1);
                SetF(8, 7, ((fb >> 6) & 1) == 1); SetF(8, 8, ((fb >> 7) & 1) == 1); SetF(7, 8, ((fb >> 8) & 1) == 1);
                for (int i = 9; i < 15; i++) SetF(14 - i, 8, ((fb >> i) & 1) == 1);
                for (int i = 0; i < 8; i++) SetF(size - 1 - i, 8, ((fb >> i) & 1) == 1);
                for (int i = 8; i < 15; i++) SetF(8, size - 15 + i, ((fb >> i) & 1) == 1);
                SetF(8, size - 8, true);
            }
            DrawFormat(0);   // reserve the format area
            if (ver >= 7)
            {
                int rem = ver;
                for (int i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
                int vb = (ver << 12) | rem;
                for (int i = 0; i < 18; i++)
                {
                    bool b = ((vb >> i) & 1) == 1; int a = size - 11 + i % 3, bb = i / 3;
                    SetF(a, bb, b); SetF(bb, a, b);
                }
            }

            // place the codewords in the zigzag order
            int bi = 0, total = outCw.Count * 8;
            for (int right = size - 1; right > 0; right -= 2)
            {
                int r = right <= 6 ? right - 1 : right;           // the vertical timing column is skipped
                for (int vert = 0; vert < size; vert++)
                    for (int j = 0; j < 2; j++)
                    {
                        int x = r - j; bool upward = ((r + 1) & 2) == 0;
                        int y = upward ? size - 1 - vert : vert;
                        if (!fn[y, x] && bi < total) { mod[y, x] = ((outCw[bi >> 3] >> (7 - (bi & 7))) & 1) == 1; bi++; }
                    }
            }

            void Apply(int m)
            {
                for (int y = 0; y < size; y++)
                    for (int x = 0; x < size; x++)
                    {
                        if (fn[y, x]) continue;
                        bool inv = m switch
                        {
                            0 => (x + y) % 2 == 0, 1 => y % 2 == 0, 2 => x % 3 == 0, 3 => (x + y) % 3 == 0,
                            4 => (x / 3 + y / 2) % 2 == 0, 5 => x * y % 2 + x * y % 3 == 0,
                            6 => (x * y % 2 + x * y % 3) % 2 == 0, _ => ((x + y) % 2 + x * y % 3) % 2 == 0
                        };
                        if (inv) mod[y, x] = !mod[y, x];
                    }
            }
            int best = 0, bestP = int.MaxValue;
            for (int m = 0; m < 8; m++)
            {
                Apply(m); DrawFormat(m);
                int p = Penalty(mod, size);
                if (p < bestP) { best = m; bestP = p; }
                Apply(m);   // undo
            }
            Apply(best); DrawFormat(best);
            version = ver; mask = best;
            return mod;
        }

        // The grid as text, one row per line ('#' dark, '.' light, rows joined by LF with no trailing LF). Used by the tests.
        public static string ToText(bool[,] m)
        {
            int n = m.GetLength(0); var sb = new StringBuilder();
            for (int y = 0; y < n; y++) { if (y > 0) sb.Append('\n'); for (int x = 0; x < n; x++) sb.Append(m[y, x] ? '#' : '.'); }
            return sb.ToString();
        }

        // An SVG path for the dark modules (one rectangle per run), with a four-module quiet zone, for a white card.
        public static string ToSvgPath(bool[,] m, int border = 4)
        {
            int n = m.GetLength(0); var sb = new StringBuilder();
            for (int y = 0; y < n; y++)
            {
                int x = 0;
                while (x < n)
                {
                    if (!m[y, x]) { x++; continue; }
                    int s = x; while (x < n && m[y, x]) x++;
                    sb.Append('M').Append(s + border).Append(' ').Append(y + border).Append('h').Append(x - s).Append("v1h-").Append(x - s).Append('z');
                }
            }
            return sb.ToString();
        }

        // ---- tables and math -------------------------------------------------------------------------------------------------
        private static int RawModules(int ver)
        {
            int r = (16 * ver + 128) * ver + 64;
            if (ver >= 2) { int na = ver / 7 + 2; r -= (25 * na - 10) * na - 55; if (ver >= 7) r -= 36; }
            return r;
        }
        private static int DataCodewords(int ver) => RawModules(ver) / 8 - EccPerBlock[ver] * NumBlocks[ver];

        private static List<int> AlignPositions(int ver)
        {
            var res = new List<int>();
            if (ver == 1) return res;
            int na = ver / 7 + 2, step = (ver * 4 + na * 2 + 1) / (na * 2 - 2) * 2, size = ver * 4 + 17;
            res.Add(6); int pos = size - 7;
            for (int i = 0; i < na - 1; i++) { res.Insert(1, pos); pos -= step; }
            return res;
        }

        private static int GfMul(int x, int y)
        {
            int z = 0;
            for (int i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >> 7) * 0x11D); z ^= ((y >> i) & 1) * x; }
            return z;
        }
        private static int[] RsDivisor(int degree)
        {
            var res = new int[degree]; res[degree - 1] = 1; int root = 1;
            for (int i = 0; i < degree; i++)
            {
                for (int j = 0; j < degree; j++) { res[j] = GfMul(res[j], root); if (j + 1 < degree) res[j] ^= res[j + 1]; }
                root = GfMul(root, 0x02);
            }
            return res;
        }
        private static int[] RsRemainder(int[] data, int[] divisor)
        {
            var res = new int[divisor.Length];
            foreach (var b in data)
            {
                int factor = b ^ res[0];
                Array.Copy(res, 1, res, 0, res.Length - 1); res[res.Length - 1] = 0;
                for (int i = 0; i < res.Length; i++) res[i] ^= GfMul(divisor[i], factor);
            }
            return res;
        }

        // the four penalty rules of the specification
        private static int Penalty(bool[,] mod, int size)
        {
            int p = 0;
            for (int pass = 0; pass < 2; pass++)
                for (int a = 0; a < size; a++)
                {
                    var sb = new StringBuilder(size); int run = 1;
                    for (int b = 0; b < size; b++)
                    {
                        bool v = pass == 0 ? mod[a, b] : mod[b, a];
                        sb.Append(v ? '1' : '0');
                        if (b > 0)
                        {
                            bool prev = pass == 0 ? mod[a, b - 1] : mod[b - 1, a];
                            if (v == prev) run++;
                            else { if (run >= 5) p += 3 + run - 5; run = 1; }
                        }
                    }
                    if (run >= 5) p += 3 + run - 5;
                    var s = sb.ToString();
                    p += 40 * (CountNonOverlapping(s, "10111010000") + CountNonOverlapping(s, "00001011101"));
                }
            for (int y = 0; y < size - 1; y++)
                for (int x = 0; x < size - 1; x++)
                {
                    bool v = mod[y, x];
                    if (v == mod[y, x + 1] && v == mod[y + 1, x] && v == mod[y + 1, x + 1]) p += 3;
                }
            int dark = 0; for (int y = 0; y < size; y++) for (int x = 0; x < size; x++) if (mod[y, x]) dark++;
            int tot = size * size;
            int kk = (Math.Abs(dark * 20 - tot * 10) + tot - 1) / tot - 1;
            return p + kk * 10;
        }

        private static int CountNonOverlapping(string s, string pat)
        {
            int c = 0, i = 0;
            while ((i = s.IndexOf(pat, i, StringComparison.Ordinal)) >= 0) { c++; i += pat.Length; }
            return c;
        }
    }
}
