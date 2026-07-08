#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <limits>
using namespace std;

const unsigned char H1 = 0xAA, H2 = 0x55, F1 = 0x55, F2 = 0xAA;
const int MAX_DATA_LEN = 255;
const int BUF_SIZE = 512;

// 接收端解析出来的一帧数据
struct DataFrame {
    unsigned char length;
    unsigned char* data;
    unsigned char checksum;
};

// 简化历史记录：保留链表练习重点
struct CommRecord {
    int id;
    char* original;
    bool checksumPassed;
    bool interference;
    CommRecord* next;
};

CommRecord* g_historyHead = 0;
int g_recordCount = 0;

char* copyString(const char* src) {
    char* dest = new char[strlen(src) + 1];
    strcpy(dest, src);
    return dest;
}

char* bytesToHex(const unsigned char* data, int len) {
    if (len <= 0) return copyString("");
    const char hexChars[] = "0123456789ABCDEF";
    char* text = new char[len * 3];
    int pos = 0;
    for (int i = 0; i < len; i++) {
        text[pos++] = hexChars[data[i] / 16];
        text[pos++] = hexChars[data[i] % 16];
        if (i != len - 1) text[pos++] = ' ';
    }
    text[pos] = '\0';
    return text;
}

void copyBytes(unsigned char* dest, const unsigned char* src, int len) {
    for (int i = 0; i < len; i++) dest[i] = src[i];
}

// 校验和：把所有载荷字节逐个异或
unsigned char calcChecksum(const unsigned char* data, int len) {
    unsigned char sum = 0;
    for (int i = 0; i < len; i++) sum = sum ^ data[i];
    return sum;
}

bool verifyChecksum(const unsigned char* data, int len, unsigned char checksum) {
    return calcChecksum(data, len) == checksum;
}

// 两种简单加密：XOR 和凯撒
void xorEncrypt(unsigned char* data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) data[i] = data[i] ^ key;
}

void caesarEncrypt(unsigned char* data, int len, int shift) {
    for (int i = 0; i < len; i++) {
        int value = (int)data[i] + shift;
        while (value < 0) value += 256;
        data[i] = (unsigned char)(value % 256);
    }
}

void cryptByMethod(unsigned char* data, int len, int method, int key, bool decrypt) {
    if (method == 1) xorEncrypt(data, len, (unsigned char)key);
    else caesarEncrypt(data, len, decrypt ? -key : key);
}

// 协议帧：帧头 + 长度 + 加密载荷 + 校验和 + 帧尾
void buildFrame(const unsigned char* data, int len, unsigned char* frame) {
    frame[0] = H1;
    frame[1] = H2;
    frame[2] = (unsigned char)len;
    copyBytes(frame + 3, data, len);
    frame[3 + len] = calcChecksum(data, len);
    frame[4 + len] = F1;
    frame[5 + len] = F2;
}

bool parseFrame(const unsigned char* frame, int frameLen, DataFrame* out) {
    out->length = 0;
    out->data = 0;
    out->checksum = 0;
    if (frame == 0 || frameLen < 6) return false;
    if (frame[0] != H1 || frame[1] != H2) return false;
    if (frame[frameLen - 2] != F1 || frame[frameLen - 1] != F2) return false;

    int len = (int)frame[2];
    if (len + 6 != frameLen) return false;

    out->length = frame[2];
    out->checksum = frame[3 + len];
    if (len > 0) {
        out->data = new unsigned char[len];
        copyBytes(out->data, frame + 3, len);
    }
    return true;
}

void freeFrame(DataFrame* frame) {
    if (frame->data != 0) {
        delete[] frame->data;
        frame->data = 0;
    }
}

// 传输干扰：随机翻转一个 bit
void injectError(unsigned char* frame, int frameLen) {
    int byteIndex = rand() % frameLen;
    int bitIndex = rand() % 8;
    frame[byteIndex] = frame[byteIndex] ^ (unsigned char)(1 << bitIndex);
}

bool transmitWithResult(unsigned char* frame, int frameLen, double rate) {
    if (rate <= 0) return false;
    if (rate > 1) rate = 1;
    if ((double)rand() / RAND_MAX <= rate) {
        injectError(frame, frameLen);
        return true;
    }
    return false;
}

void transmit(unsigned char* frame, int frameLen, double rate) {
    transmitWithResult(frame, frameLen, rate);
}

// 历史记录链表
void addRecord(const char* original, bool checksumOk, bool interference) {
    CommRecord* node = new CommRecord;
    node->id = g_recordCount + 1;
    node->original = copyString(original);
    node->checksumPassed = checksumOk;
    node->interference = interference;
    node->next = g_historyHead;
    g_historyHead = node;
    g_recordCount++;
}

void showHistory() {
    cout << endl << "========== 通信历史 ==========" << endl;
    if (g_historyHead == 0) {
        cout << "暂无记录。" << endl;
        return;
    }
    CommRecord* p = g_historyHead;
    while (p != 0) {
        cout << "编号: " << p->id << endl;
        cout << "原文: " << p->original << endl;
        cout << "校验: " << (p->checksumPassed ? "通过" : "失败") << endl;
        cout << "干扰: " << (p->interference ? "是" : "否") << endl;
        cout << "------------------------------" << endl;
        p = p->next;
    }
}

void freeHistory() {
    CommRecord* p = g_historyHead;
    while (p != 0) {
        CommRecord* next = p->next;
        delete[] p->original;
        delete p;
        p = next;
    }
    g_historyHead = 0;
    g_recordCount = 0;
}

void displayFrame(const unsigned char* frame, int len) {
    for (int i = 0; i < len; i++) {
        cout << uppercase << hex << setw(2) << setfill('0') << (int)frame[i] << " ";
        if ((i + 1) % 16 == 0) cout << endl;
    }
    cout << dec << setfill(' ') << endl;
}

void showProtocolInfo() {
    cout << endl << "协议帧格式:" << endl;
    cout << "帧头 AA 55 | 长度 1B | 加密载荷 | 校验和 | 帧尾 55 AA" << endl;
    cout << "发送顺序: 原文 -> 加密 -> 计算校验和 -> 封装 -> 传输 -> 校验 -> 解密" << endl;
}

#ifndef UNIT_TEST
int readInt(const char* prompt, int minValue, int maxValue) {
    int value;
    while (true) {
        cout << prompt;
        cin >> value;
        if (!cin.fail() && value >= minValue && value <= maxValue) {
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            return value;
        }
        cout << "输入无效，请重新输入。" << endl;
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    }
}

void showMenu() {
    cout << endl;
    cout << "===== 轻量级物联网加密通信协议 =====" << endl;
    cout << "1. 发送数据" << endl;
    cout << "2. 查看历史" << endl;
    cout << "3. 协议说明" << endl;
    cout << "4. 退出" << endl;
}

void pauseScreen() {
    cout << endl << "按回车键继续...";
    cin.get();
}

void getMethod(int* method, int* key, char* methodName) {
    *method = readInt("选择加密方式 (1.XOR 2.凯撒): ", 1, 2);
    if (*method == 1) {
        *key = readInt("输入 XOR 密钥 (0-255): ", 0, 255);
        strcpy(methodName, "XOR");
    } else {
        *key = readInt("输入凯撒偏移量 (0-255): ", 0, 255);
        strcpy(methodName, "Caesar");
    }
}

bool receiveAndDecrypt(unsigned char* frame, int frameLen, int method, int key) {
    DataFrame parsed;
    if (!parseFrame(frame, frameLen, &parsed)) {
        cout << "解析失败: 帧头、帧尾或长度错误。" << endl;
        return false;
    }

    bool ok = verifyChecksum(parsed.data, parsed.length, parsed.checksum);
    if (!ok) {
        cout << "校验失败: 数据可能被干扰。" << endl;
        freeFrame(&parsed);
        return false;
    }

    unsigned char* text = new unsigned char[parsed.length + 1];
    copyBytes(text, parsed.data, parsed.length);
    cryptByMethod(text, parsed.length, method, key, true);
    text[parsed.length] = '\0';
    cout << "校验通过，解密结果: " << (char*)text << endl;

    delete[] text;
    freeFrame(&parsed);
    return true;
}

void sendDataFlow() {
    char input[BUF_SIZE], methodName[20];
    int method, key;

    cout << endl << "请输入要发送的文本: ";
    cin.getline(input, BUF_SIZE);
    if (cin.fail()) {
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    }

    int len = (int)strlen(input);
    if (len > MAX_DATA_LEN) {
        cout << "输入过长，最多 255 字节。" << endl;
        return;
    }

    getMethod(&method, &key, methodName);
    unsigned char* payload = new unsigned char[len == 0 ? 1 : len];
    for (int i = 0; i < len; i++) payload[i] = (unsigned char)input[i];
    cryptByMethod(payload, len, method, key, false);

    int frameLen = len + 6;
    unsigned char* frame = new unsigned char[frameLen];
    unsigned char* recvFrame = new unsigned char[frameLen];
    buildFrame(payload, len, frame);
    copyBytes(recvFrame, frame, frameLen);

    char* hexText = bytesToHex(payload, len);
    cout << "加密方式: " << methodName << endl;
    cout << "加密载荷: " << hexText << endl;
    cout << "发送帧: ";
    displayFrame(frame, frameLen);

    bool changed = false;
    if (readInt("是否模拟干扰? (1.否 2.是): ", 1, 2) == 2) {
        int rate = readInt("干扰概率百分比 (0-100): ", 0, 100);
        changed = transmitWithResult(recvFrame, frameLen, rate / 100.0);
    }

    cout << "接收帧: ";
    displayFrame(recvFrame, frameLen);
    cout << "实际发生干扰: " << (changed ? "是" : "否") << endl;
    bool ok = receiveAndDecrypt(recvFrame, frameLen, method, key);
    addRecord(input, ok, changed);

    delete[] payload;
    delete[] frame;
    delete[] recvFrame;
    delete[] hexText;
}

int main() {
    srand((unsigned int)time(0));
    while (true) {
        showMenu();
        int choice = readInt("请选择: ", 1, 4);
        if (choice == 1) sendDataFlow();
        else if (choice == 2) showHistory();
        else if (choice == 3) showProtocolInfo();
        else {
            freeHistory();
            cout << "程序已退出。" << endl;
            break;
        }
        pauseScreen();
    }
    return 0;
}
#endif
