#include "../includes/historical_ciphers.h"
#include <vector>
#include <cctype>
#include <algorithm>

void atbash(const std::string &a, std::string &out){
    out="";
    for (char c:a) {
        if (c>='a' && c<='z') {
            out+=(char)('z'-(c-'a'));
        } else if (c>='A' && c<='Z') {
            out+=(char)('Z'-(c-'A'));
        } else {
            out+=c;
        }
    }
}

void caesar(const std::string &a, std::string &out){
    custom_rot(a, 3, out);
}

void vigenere(const std::string &a, const std::string &key, std::string &out, bool encrypt) {
    int klen=key.length();
    int ki=0;
    int sign=encrypt?1:-1;
    out="";
    for (char c : a) {
        char k = key[ki % klen];
        int shift = (k >= 'a' && k <= 'z') ? k - 'a' : k - 'A';
        if (c >= 'a' && c <= 'z') {
            out += (char)(((c - 'a') + sign * shift + 26) % 26 + 'a');
            ki++;
        } else if (c >= 'A' && c <= 'Z') {
            out += (char)(((c - 'A') + sign * shift + 26) % 26 + 'A');
            ki++;
        } else {
            out += c;
        }
    }
}

void autokey(const std::string &a, const std::string &key, std::string &out, bool encrypt) {
    std::string k = key;
    int ki = 0;
    int sign = encrypt ? 1 : -1;
    out = "";
    for (char c : a) {
        int shift = (k[ki] >= 'a' && k[ki] <= 'z') ? k[ki] - 'a' : k[ki] - 'A';
        if (c >= 'a' && c <= 'z') {
            char p = (char)(((c - 'a') + sign * shift + 26) % 26 + 'a');
            out += p;
            k += encrypt ? c : p;
            ki++;
        } else if (c >= 'A' && c <= 'Z') {
            char p = (char)(((c - 'A') + sign * shift + 26) % 26 + 'A');
            out += p;
            k += encrypt ? c : p;
            ki++;
        } else {
            out += c;
        }
    }
}

void beaufort(const std::string &a, const std::string &key, std::string &out) {
    int klen=key.length(), ki=0;
    out="";
    for (char c:a) {
        if (c>='a' && c<='z') {
            int shift=key[ki%klen]-'a';
            out+=(char)((shift-(c-'a')+26*26)%26+'a');
            ki++;
        } else if (c>='A' && c<='Z') {
            int shift=key[ki%klen]-'A';
            out+=(char)((shift-(c-'A')+26)%26+'A');
            ki++;
        } else {
            out+=c;
        }
    }
}

void railfence(const std::string &a, std::string &out, int key, int offset) {
    out="";
    int n=a.length(), cyc=2*(key - 1);
    for (int r=0; r<key; r++) {
        for (int j=0; j<n; j++) {
            int p=(j+offset)%cyc;
            int rail=p<key?p:cyc-p;
            if (rail==r)
                out+=a[j];
        }
    }
}

void scytale_encrypt(const std::string &a, std::string &out, int m) {
    out = "";
    int n = a.length();
    int cols = (n + m - 1) / m;
    int extra = n % m;
    std::vector<int> row_len(m), row_start(m);
    row_start[0] = 0;
    for (int i = 0; i < m; i++) {
        row_len[i] = (extra == 0 || i < extra) ? cols : cols - 1;
        if (i > 0) row_start[i] = row_start[i-1] + row_len[i-1];
    }
    for (int col = 0; col < cols; col++)
        for (int row = 0; row < m; row++)
            if (col < row_len[row])
                out += a[row_start[row] + col];
}

void scytale_decrypt(const std::string &a, std::string &out, int m) {
    out = "";
    int n = a.length();
    int cols = (n + m - 1) / m;
    int extra = n % m;
    std::vector<int> row_len(m), row_start(m);
    row_start[0] = 0;
    for (int i = 0; i < m; i++) {
        row_len[i] = (extra == 0 || i < extra) ? cols : cols - 1;
        if (i > 0) row_start[i] = row_start[i-1] + row_len[i-1];
    }
    std::string grid(n, ' ');
    int src = 0;
    for (int col = 0; col < cols; col++)
        for (int row = 0; row < m; row++)
            if (col < row_len[row])
                grid[row_start[row] + col] = a[src++];
    out = grid;
}

void polybius_encrypt(const std::string &alphabet, const std::string &a, std::string &out) {
    out = "";
    char grid[6][6];
    for (int i = 1; i <= 5; i++)
        for (int j = 1; j <= 5; j++)
            grid[i][j] = alphabet[(i-1) * 5 + (j-1)];
    for (char c : a) {
        for (int i = 1; i <= 5; i++) {
            for (int j = 1; j <= 5; j++) {
                if (grid[i][j] == c) {
                    out += (char)('0' + i);
                    out += (char)('0' + j);
                }
            }
        }
    }
}

void polybius_decrypt(const std::string &alphabet, const std::string &a, std::string &out) {
    out = "";
    char grid[6][6];
    for (int i = 1; i <= 5; i++)
        for (int j = 1; j <= 5; j++)
            grid[i][j] = alphabet[(i-1) * 5 + (j-1)];
    int n = a.length();
    for (int i = 0; i + 1 < n; i += 2) {
        int ci = a[i]   - '0';
        int cj = a[i+1] - '0';
        out += grid[ci][cj];
    }
}

void columnar_encrypt(const std::string &a, std::string &out, const std::string &key) {
    out = "";
    int cols = key.length();
    int n = a.length();
    int rows = (n + cols - 1) / cols;
    int total = rows * cols;
    std::string padded = a;
    while ((int)padded.length() < total) padded += 'x';
    std::string sorted_key = key;
    for (int i = 0; i < cols-1; i++)
        for (int j = 0; j < cols-i-1; j++)
            if (sorted_key[j] > sorted_key[j+1])
                std::swap(sorted_key[j], sorted_key[j+1]);
    std::string used(cols, '0');
    std::vector<int> order(cols);
    for (int i = 0; i < cols; i++) {
        for (int j = 0; j < cols; j++) {
            if (key[j] == sorted_key[i] && used[j] == '0') {
                order[i] = j;
                used[j] = '1';
                break;
            }
        }
    }
    for (int i = 0; i < cols; i++) {
        int col = order[i];
        for (int row = 0; row < rows; row++) {
            out += padded[row * cols + col];
        }
    }
}

void columnar_decrypt(const std::string &a, std::string &out, const std::string &key, int original_len) {
    out = "";
    int cols = key.length();
    int rows = a.length() / cols;
    int total = rows * cols;

    std::string sorted_key = key;
    for (int i = 0; i < cols-1; i++)
        for (int j = 0; j < cols-i-1; j++)
            if (sorted_key[j] > sorted_key[j+1])
                std::swap(sorted_key[j], sorted_key[j+1]);

    std::string used(cols, '0');
    std::vector<int> order(cols);
    for (int i = 0; i < cols; i++) {
        for (int j = 0; j < cols; j++) {
            if (key[j] == sorted_key[i] && used[j] == '0') {
                order[i] = j;
                used[j] = '1';
                break;
            }
        }
    }

    std::string grid(total, ' ');
    for (int i = 0; i < cols; i++) {
        int col = order[i];
        for (int row = 0; row < rows; row++) {
            grid[row * cols + col] = a[i * rows + row];
        }
    }

    for (int i = 0; i < original_len; i++)
        out += grid[i];
}

void build_playfair_grid(const std::string &key, char grid[5][5]) {
    bool used[26] = {};
    used['J'-'A'] = true;
    std::string sequence;
    for (char c : key) {
        if (c >= 'a' && c <= 'z') c = c-'a'+'A';
        if (c < 'A' || c > 'Z') continue;
        if (c == 'J') c = 'I';
        if (!used[c-'A']) { sequence += c; used[c-'A'] = true; }
    }
    for (char c = 'A'; c <= 'Z'; c++)
        if (!used[c-'A']) sequence += c;
    for (int i = 0; i < 25; i++) grid[i/5][i%5] = sequence[i];
}

void playfair_find(char grid[5][5], char c, int &r, int &col) {
    if (c == 'J') c = 'I';
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 5; j++)
            if (grid[i][j] == c) { r = i; col = j; return; }
}

void playfair(const std::string &a, std::string &out, const std::string &key, bool encrypt) {
    out = "";
    char grid[5][5];
    build_playfair_grid(key, grid);
    int dir = encrypt?1:-1;
    std::string clean;
    for (char c : a) {
        if (c >= 'a' && c <= 'z') c = c-'a'+'A';
        if (c == 'J') c = 'I';
        if (c >= 'A' && c <= 'Z') clean += c;
    }
    std::string prep;
    int i = 0;
    while (i < (int)clean.length()) {
        prep += clean[i];
        if (i+1 < (int)clean.length()) {
            if (clean[i] == clean[i+1]) { prep += 'X'; }
            else { prep += clean[i+1]; i++; }
        }
        i++;
    }
    if (prep.length() % 2 != 0) prep += 'X';
    for (int k = 0; k < (int)prep.length(); k += 2) {
        char p1 = prep[k], p2 = prep[k+1];
        int r1, c1, r2, c2;
        playfair_find(grid, p1, r1, c1);
        playfair_find(grid, p2, r2, c2);
        if (r1 == r2) {
            out += grid[r1][(c1 + dir + 5) % 5];
            out += grid[r2][(c2 + dir + 5) % 5];
        } else if (c1 == c2) {
            out += grid[(r1 + dir + 5) % 5][c1];
            out += grid[(r2 + dir + 5) % 5][c2];
        } else {
            out += grid[r1][c2];
            out += grid[r2][c1];
        }
    }
}

void build_bifid_grid(const std::string rows[5], char grid[6][6], int row_of[256], int col_of[256]) {
    for (int i = 1; i <= 5; i++)
        for (int j = 1; j <= 5; j++) {
            char ch = rows[i-1][j-1];
            grid[i][j] = ch;
            row_of[(int)ch] = i;
            col_of[(int)ch] = j;
        }
}

void bifid_encrypt(const std::string &msg, std::string &out, char grid[6][6], int row_of[256], int col_of[256]) {
    int n = msg.size();
    int flat[20001];
    for (int i = 0; i < n; i++) flat[i]     = row_of[(int)msg[i]];
    for (int i = 0; i < n; i++) flat[n + i] = col_of[(int)msg[i]];
    out = "";
    for (int i = 0; i < 2*n; i += 2)
        out += grid[flat[i]][flat[i+1]];
}

void bifid_decrypt(const std::string &msg, std::string &out, char grid[6][6], int row_of[256], int col_of[256]) {
    int n = msg.size();
    int flat[20001];
    for (int i = 0; i < n; i++) {
        flat[2*i]     = row_of[(int)msg[i]];
        flat[2*i + 1] = col_of[(int)msg[i]];
    }
    out = "";
    for (int i = 0; i < n; i++)
        out += grid[flat[i]][flat[n + i]];
}

int mod_inverse(int a, int m) {
    a = ((a % m) + m) % m;
    for (int x = 1; x < m; x++)
        if ((a * x) % m == 1) return x;
    return -1;
}

void affine(const std::string &a, std::string &out, int ka, int kb, bool encrypt) {
    out = "";
    int inv = mod_inverse(ka, 26);
    if (inv == -1) { out = "[ERROR: key 'a' must be coprime to 26]"; return; }
    for (char c : a) {
        if (c >= 'a' && c <= 'z') {
            int x = c - 'a';
            int r = encrypt ? (ka * x + kb) % 26 : (inv * (x - kb + 26 * 26)) % 26;
            out += (char)(r + 'a');
        } else if (c >= 'A' && c <= 'Z') {
            int x = c - 'A';
            int r = encrypt ? (ka * x + kb) % 26 : (inv * (x - kb + 26 * 26)) % 26;
            out += (char)(r + 'A');
        } else {
            out += c;
        }
    }
}

void build_trifid_grid(const std::string &key, char grid[3][3][3]) {
    bool used[27] = {};
    std::string sequence;
    for (char c : key) {
        if (c >= 'a' && c <= 'z') c = c-'a'+'A';
        if (c == '+' && !used[26]) { sequence += '+'; used[26] = true; continue; }
        if (c < 'A' || c > 'Z') continue;
        if (!used[c-'A']) { sequence += c; used[c-'A'] = true; }
    }
    for (char c = 'A'; c <= 'Z'; c++) if (!used[c-'A']) { sequence += c; used[c-'A'] = true; }
    if (!used[26]) sequence += '+';
    for (int i = 0; i < 27; i++) grid[i/9][(i%9)/3][i%3] = sequence[i];
}

void trifid_find(char grid[3][3][3], char c, int &la, int &r, int &col) {
    if (c >= 'a' && c <= 'z') c = c-'a'+'A';
    for (int l = 0; l < 3; l++)
        for (int i = 0; i < 3; i++)
            for (int j = 0; j < 3; j++)
                if (grid[l][i][j] == c) { la = l; r = i; col = j; return; }
}

char trifid_char(char grid[3][3][3], int la, int r, int col) {
    return grid[la][r][col];
}

void trifid(const std::string &a, std::string &out, const std::string &key, int period, bool encrypt) {
    out = "";
    char grid[3][3][3];
    build_trifid_grid(key, grid);
    std::string clean;
    for (char c : a) {
        if (c >= 'a' && c <= 'z') c = c-'a'+'A';
        if ((c >= 'A' && c <= 'Z') || c == '+') clean += c;
    }
    size_t n = clean.length();
    for (size_t start = 0; start < n; start += period) {
        size_t end = start + period;
        if (end > n) end = n;
        int blen = (int)(end - start);
        std::vector<int> layers(blen), rows(blen), cols(blen);
        for (int i = 0; i < blen; i++)
            trifid_find(grid, clean[start+i], layers[i], rows[i], cols[i]);
        if (encrypt) {
            std::vector<int> flat(blen * 3);
            for (int i = 0; i < blen; i++) { flat[i]        = layers[i]; }
            for (int i = 0; i < blen; i++) { flat[blen+i]   = rows[i]; }
            for (int i = 0; i < blen; i++) { flat[2*blen+i] = cols[i]; }
            for (int i = 0; i < blen; i++)
                out += trifid_char(grid, flat[i], flat[blen+i], flat[2*blen+i]);
        } else {
            std::vector<int> flat(blen * 3);
            for (int i = 0; i < blen; i++) {
                trifid_find(grid, clean[start+i], flat[i], flat[blen+i], flat[2*blen+i]);
            }
            for (int i = 0; i < blen; i++)
                out += trifid_char(grid, flat[i], flat[blen+i], flat[2*blen+i]);
        }
    }
}

void build_foursquare_grid(const std::string &key, char grid[5][5]) {
    bool used[26] = {};
    used['J'-'A'] = true;
    std::string sequence;
    for (char c : key) {
        if (c >= 'a' && c <= 'z') c = c-'a'+'A';
        if (c < 'A' || c > 'Z') continue;
        if (c == 'J') c = 'I';
        if (!used[c-'A']) { sequence += c; used[c-'A'] = true; }
    }
    for (char c = 'A'; c <= 'Z'; c++)
        if (!used[c-'A']) sequence += c;
    for (int i = 0; i < 25; i++) grid[i/5][i%5] = sequence[i];
}

void build_standard_grid(char grid[5][5]) {
    const std::string std_alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
    for (int i = 0; i < 25; i++) grid[i/5][i%5] = std_alpha[i];
}

void foursquare_find(char grid[5][5], char c, int &r, int &col) {
    if (c == 'J') c = 'I';
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 5; j++)
            if (grid[i][j] == c) { r = i; col = j; return; }
}

void four_square(const std::string &a, std::string &out, const std::string &key1, const std::string &key2, bool encrypt) {
    out = "";
    char plain[5][5], cipher1[5][5], cipher2[5][5];
    build_standard_grid(plain);
    build_foursquare_grid(key1, cipher1);
    build_foursquare_grid(key2, cipher2);
    std::string clean;
    for (char c : a) {
        if (c >= 'a' && c <= 'z') c = c-'a'+'A';
        if (c == 'J') c = 'I';
        if (c >= 'A' && c <= 'Z') clean += c;
    }
    if (clean.length() % 2 != 0) clean += 'X';
    for (int k = 0; k < (int)clean.length(); k += 2) {
        int r1, c1, r2, c2;
        if (encrypt) {
            foursquare_find(plain,   clean[k],   r1, c1);
            foursquare_find(plain,   clean[k+1], r2, c2);
            out += cipher1[r1][c2];
            out += cipher2[r2][c1];
        } else {
            foursquare_find(cipher1, clean[k],   r1, c1);
            foursquare_find(cipher2, clean[k+1], r2, c2);
            out += plain[r1][c2];
            out += plain[r2][c1];
        }
    }
}

const char ADFGVX_LETTERS[6] = {'A','D','F','G','V','X'};

void build_adfgvx_grid(const std::string &key, char grid[6][6]) {
    bool used[36] = {};
    std::string sequence;
    for (char c : key) {
        int idx = -1;
        if (c >= 'A' && c <= 'Z') idx = c - 'A';
        else if (c >= 'a' && c <= 'z') idx = c - 'a';
        else if (c >= '0' && c <= '9') idx = 26 + c - '0';
        if (idx != -1 && !used[idx]) { sequence += (char)(idx < 26 ? 'A'+idx : '0'+idx-26); used[idx] = true; }
    }
    for (char c = 'A'; c <= 'Z'; c++) { int idx = c-'A'; if (!used[idx]) { sequence += c; used[idx] = true; } }
    for (char c = '0'; c <= '9'; c++) { int idx = 26+c-'0'; if (!used[idx]) { sequence += c; used[idx] = true; } }
    for (int i = 0; i < 36; i++) grid[i/6][i%6] = sequence[i];
}

void adfgvx_find(char grid[6][6], char c, int &r, int &col) {
    if (c >= 'a' && c <= 'z') c = c-'a'+'A';
    for (int i = 0; i < 6; i++)
        for (int j = 0; j < 6; j++)
            if (grid[i][j] == c) { r = i; col = j; return; }
}

void adfgvx_columnar_encrypt(const std::string &a, std::string &out, const std::string &key) {
    int cols = key.length();
    int rows = (a.length() + cols - 1) / cols;
    int total = rows * cols;
    std::string padded = a;
    while ((int)padded.length() < total) padded += 'A';
    std::vector<int> order(cols);
    std::string used(cols, '0');
    std::string sorted_key = key;
    for (int i = 0; i < cols-1; i++)
        for (int j = 0; j < cols-i-1; j++)
            if (sorted_key[j] > sorted_key[j+1]) std::swap(sorted_key[j], sorted_key[j+1]);
    for (int i = 0; i < cols; i++) {
        for (int j = 0; j < cols; j++) {
            if (key[j] == sorted_key[i] && used[j] == '0') { order[i] = j; used[j] = '1'; break; }
        }
    }
    out = "";
    for (int i = 0; i < cols; i++)
        for (int row = 0; row < rows; row++)
            out += padded[row * cols + order[i]];
}

void adfgvx_columnar_decrypt(const std::string &a, std::string &out, const std::string &key) {
    int cols = key.length();
    int rows = a.length() / cols;
    int total = rows * cols;
    std::vector<int> order(cols);
    std::string used(cols, '0');
    std::string sorted_key = key;
    for (int i = 0; i < cols-1; i++)
        for (int j = 0; j < cols-i-1; j++)
            if (sorted_key[j] > sorted_key[j+1]) std::swap(sorted_key[j], sorted_key[j+1]);
    for (int i = 0; i < cols; i++) {
        for (int j = 0; j < cols; j++) {
            if (key[j] == sorted_key[i] && used[j] == '0') { order[i] = j; used[j] = '1'; break; }
        }
    }
    std::string grid(total, ' ');
    for (int i = 0; i < cols; i++)
        for (int row = 0; row < rows; row++)
            grid[row * cols + order[i]] = a[i * rows + row];
    out = grid;
}

void adfgvx(const std::string &a, std::string &out, const std::string &polybius_key, const std::string &col_key, bool encrypt) {
    out = "";
    char grid[6][6];
    build_adfgvx_grid(polybius_key, grid);
    if (encrypt) {
        std::string substituted;
        for (char c : a) {
            int r, col;
            adfgvx_find(grid, c, r, col);
            substituted += ADFGVX_LETTERS[r];
            substituted += ADFGVX_LETTERS[col];
        }
        adfgvx_columnar_encrypt(substituted, out, col_key);
    } else {
        std::string substituted;
        adfgvx_columnar_decrypt(a, substituted, col_key);
        for (int i = 0; i+1 < (int)substituted.length(); i += 2) {
            int r = -1, col = -1;
            for (int k = 0; k < 6; k++) {
                if (ADFGVX_LETTERS[k] == substituted[i])   r   = k;
                if (ADFGVX_LETTERS[k] == substituted[i+1]) col = k;
            }
            if (r != -1 && col != -1) out += grid[r][col];
        }
    }
}

void bacon(const std::string &a, std::string &out, bool encrypt) {
    out = "";
    if (encrypt) {
        for (char c : a) {
            if (c >= 'a' && c <= 'z') c = c - 'a' + 'A';
            if (c >= 'A' && c <= 'Z') {
                int n = c - 'A';
                for (int bit = 4; bit >= 0; bit--)
                    out += ((n >> bit) & 1) ? 'B' : 'A';
                out += ' ';
            } else {
                out += c;
            }
        }
    } else {
        std::string token;
        for (char c : a + " ") {
            if (c == 'A' || c == 'B' || c == 'a' || c == 'b') {
                token += (char)toupper(c);
                if ((int)token.length() == 5) {
                    int n = 0;
                    for (char b : token) n = n * 2 + (b == 'B' ? 1 : 0);
                    if (n < 26) out += (char)('A' + n);
                    token = "";
                }
            } else {
                if (!token.empty()) token = "";
                if (c != ' ') out += c;
            }
        }
    }
}

void morse_encode(const std::string &a, std::string &out){
    out="";
    for (char c:a){
        char lower=tolower(c);
        size_t pos=alphabet_to_morse.find(lower);
        if (pos!=std::string::npos){
            out+=morse_to_alphabet[pos]+" ";
        }
    }
}

void morse_decode(const std::string &a, std::string &out) {
    out = "";
    std::string token;
    for (char c : a + " ") {
        if (c == ' ') {
            if (token.empty()) continue;
            if (token == "/") {
                out += ' ';
            } else {
                for (int i = 0; i < 37; i++) {
                    if (morse_to_alphabet[i] == token) {
                        out += alphabet_to_morse[i];
                        break;
                    }
                }
            }
            token = "";
        } else {
            token += c;
        }
    }
}

void braille_to_dots(const std::string &cell, std::string &out) {
    out = "";
    if (cell.length() != 6) return;
    out += (cell[0]=='1') ? "● " : "○ ";
    out += (cell[1]=='1') ? "●" : "○";
    out += "\n";
    out += (cell[2]=='1') ? "● " : "○ ";
    out += (cell[3]=='1') ? "●" : "○";
    out += "\n";
    out += (cell[4]=='1') ? "● " : "○ ";
    out += (cell[5]=='1') ? "●" : "○";
    out += "\n";
}

void braille_print_dots(const std::string &a) {
    std::string token;
    for (char c : a + " ") {
        if (c == ' ') {
            if (token.empty()) continue;
            if (token == NUMBER_INDICATOR) {
                std::cout << "[NUM]\n";
            } else if (token == LETTER_INDICATOR) {
                std::cout << "[LET]\n";
            } else {
                std::string dots;
                braille_to_dots(token, dots);
                std::cout << dots << "\n";
            }
            token = "";
        } else {
            token += c;
        }
    }
}

void simple_dots_to_braille(const std::string &dots, std::string &out) {
    out = "";
    for (char c : dots) {
        if (c == '#') out += '1';
        else if (c == '.') out += '0';
    }
}

void braille_to_simple_dots(const std::string &cell, std::string &out) {
    out = "";
    if (cell.length() != 6) return;
    out += (cell[0]=='1') ? "# " : ". ";
    out += (cell[1]=='1') ? "#" : ".";
    out += "\n";
    out += (cell[2]=='1') ? "# " : ". ";
    out += (cell[3]=='1') ? "#" : ".";
    out += "\n";
    out += (cell[4]=='1') ? "# " : ". ";
    out += (cell[5]=='1') ? "#" : ".";
    out += "\n";
}

void braille_encode(const std::string &a, std::string &out) {
    out = "";
    bool in_number_mode = false;
    for (char c : a) {
        if (isdigit(c)) {
            if (!in_number_mode) {
                out += NUMBER_INDICATOR + " ";
                in_number_mode = true;
            }
            out += digit_map[c - '0'] + " ";
        } else {
            if (in_number_mode) {
                out += LETTER_INDICATOR + " ";
                in_number_mode = false;
            }
            char lower = tolower(c);
            size_t pos = braille_alphabet.find(lower);
            if (pos != std::string::npos) {
                out += braille_map[pos] + " ";
            }
        }
    }
}

void braille_decode(const std::string &a, std::string &out) {
    out = "";
    std::string token;
    bool in_number_mode = false;
    for (char c : a + " ") {
        if (c == ' ') {
            if (token.empty()) continue;
            if (token == NUMBER_INDICATOR) {
                in_number_mode = true;
            } else if (token == LETTER_INDICATOR) {
                in_number_mode = false;
            } else if (token == "000000") {
                out += ' ';
                in_number_mode = false;
            } else if (in_number_mode) {
                for (int i = 0; i < 10; i++) {
                    if (digit_map[i] == token) {
                        out += (char)('0' + i);
                        break;
                    }
                }
            } else {
                for (int i = 0; i < 27; i++) {
                    if (braille_map[i] == token) {
                        out += braille_alphabet[i];
                        break;
                    }
                }
            }
            token = "";
        } else {
            token += c;
        }
    }
}
