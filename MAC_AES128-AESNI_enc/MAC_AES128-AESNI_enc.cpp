#include <iostream>
#include <iomanip> // setfill(),setw()を使用
#include <wmmintrin.h> //AES_NIヘッダファイル
#include <vector> // メモリの動的確保に使用
#include <chrono> // 時間の計測に使用

void makeMAC_CBC(std::vector<unsigned char> input, unsigned char* mac, const unsigned char* key);
void AES_128_Key_Expansion(const unsigned char* userkey, unsigned char* encrypt_keys);
void AES_encrypt(__m128i* input, const char* encrypt_keys);

// ゼロ埋めされたstd::vectorを返す関数
std::vector<unsigned char> zeroOutMessage(size_t length) {
    std::vector<unsigned char> buffer(length); // 指定サイズのstd::vectorを確保
    std::memset(buffer.data(), 0x00, length); // メモリ全体を0x00で埋める
    return buffer;
}

int main()
{
    std::vector<unsigned char> input = zeroOutMessage(1024); // zeroOutMessage(バイト数)で指定
    const unsigned char key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; // キー（16バイト）を指定
    unsigned char mac[16];

    int rep_cnt = 1; // 計測の回数を指定
    int func_cnt = 1; // 関数の繰り返し回数を指定

    //rep_cntの回数計測する
    for (int i = 0; i < rep_cnt; i++) {

        // ↓ここから時間を計測する
        auto start = std::chrono::high_resolution_clock::now(); // 開始時間を記録

        for (int i = 0; i < func_cnt; i++) {
            makeMAC_CBC(input, mac, key);
        }
        auto end = std::chrono::high_resolution_clock::now(); // 終了時間を記録
        // ↑計測ここまで

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start); // 経過時間を計算 (ミリ秒)
        std::cout << duration.count() << std::endl;
    }

    return 0;
}

// CBCモードでMACを生成する関数
void makeMAC_CBC(std::vector<unsigned char> input, unsigned char* mac, const unsigned char* key) {
    __m128i feedfront, data;
    static unsigned char ivec[16] = { 0 }; // CBC-MACでは初期ベクトルは０
    static unsigned char buf[16]{};
    static unsigned char encrypt_keys[11 * 16]; // AES_NI-128の暗号用ラウンドキーを格納
    size_t blocks = input.size() / 16;
    size_t last_data_length = input.size() % 16;
    unsigned int i;

    AES_128_Key_Expansion(key, encrypt_keys); // 鍵拡張

    feedfront = _mm_loadu_si128((__m128i*)ivec);
    for (i = 0; i < blocks; i++) {
        data = _mm_loadu_si128(&((__m128i*)input.data())[i]);
        feedfront = _mm_xor_si128(data, feedfront);
        AES_encrypt(&feedfront, (const char*)encrypt_keys);
    }
    if (last_data_length != 0) {
        std::memcpy(buf, &((__m128i*)input.data())[i], last_data_length);
        data = _mm_loadu_si128(&((__m128i*)buf)[0]);
        feedfront = _mm_xor_si128(data, feedfront);
        AES_encrypt(&feedfront, (const char*)encrypt_keys);
    }
    ((__m128i*)mac)[0] = feedfront; // 最終ブロックの暗号文(MAC)だけ出力
}

// 鍵拡張のサポート関数
inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);
    return temp1;
}

// 鍵拡張の関数
void AES_128_Key_Expansion(const unsigned char* userkey, unsigned char* encrypt_keys) {
    __m128i temp1, temp2;
    __m128i* Key_Schedule = (__m128i*)encrypt_keys;

    temp1 = _mm_loadu_si128((__m128i*)userkey);
    Key_Schedule[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[10] = temp1;
}

// 1ブロック暗号関数
void AES_encrypt(__m128i* input, const char* encrypt_keys) {
    __m128i tmp;
    int i;

    // AES-128なので10ラウンド
    tmp = _mm_loadu_si128(input);
    tmp = _mm_xor_si128(tmp, ((__m128i*)encrypt_keys)[0]);

    for (i = 1; i < 10; i++) {
        tmp = _mm_aesenc_si128(tmp, ((__m128i*)encrypt_keys)[i]);
    }

    tmp = _mm_aesenclast_si128(tmp, ((__m128i*)encrypt_keys)[i]);
    _mm_storeu_si128(input, tmp);
}