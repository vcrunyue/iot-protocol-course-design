#define UNIT_TEST
#include "main.cpp"

#include <iostream>
#include <cstring>

int g_failedTests = 0;

void check(bool condition, const char* message) {
    if (!condition) {
        std::cout << "[FAIL] " << message << std::endl;
        g_failedTests++;
    }
}

void testXorEncryptRoundTrip() {
    unsigned char data[] = {'H', 'e', 'l', 'l', 'o'};
    unsigned char original[] = {'H', 'e', 'l', 'l', 'o'};

    xorEncrypt(data, 5, 0x12);
    check(std::memcmp(data, original, 5) != 0, "XOR should change data with non-zero key");

    xorEncrypt(data, 5, 0x12);
    check(std::memcmp(data, original, 5) == 0, "XOR should restore original data");
}

void testCaesarEncryptRoundTrip() {
    unsigned char data[] = {'S', 'e', 'n', 's', 'o', 'r'};
    unsigned char original[] = {'S', 'e', 'n', 's', 'o', 'r'};

    caesarEncrypt(data, 6, 3);
    check(std::memcmp(data, original, 6) != 0, "Caesar should change data");

    caesarEncrypt(data, 6, -3);
    check(std::memcmp(data, original, 6) == 0, "Caesar should restore original data");
}

void testChecksum() {
    unsigned char data[] = {0x10, 0x20, 0x30};
    unsigned char checksum = calcChecksum(data, 3);

    check(checksum == 0x00, "Checksum should XOR all bytes");
    check(verifyChecksum(data, 3, checksum), "Checksum verification should pass");

    data[1] ^= 0x01;
    check(!verifyChecksum(data, 3, checksum), "Checksum verification should fail after bit flip");
}

void testBuildAndParseFrame() {
    unsigned char data[] = {'A', 'B', 'C'};
    int frameLen = 3 + 6;
    unsigned char frame[9];

    buildFrame(data, 3, frame);

    check(frame[0] == 0xAA && frame[1] == 0x55, "Frame header should be correct");
    check(frame[2] == 3, "Frame length should be payload length");
    check(frame[7] == 0x55 && frame[8] == 0xAA, "Frame footer should be correct");

    DataFrame parsed;
    bool ok = parseFrame(frame, frameLen, &parsed);
    check(ok, "Valid frame should parse");
    check(parsed.length == 3, "Parsed length should match");
    check(std::memcmp(parsed.data, data, 3) == 0, "Parsed payload should match");
    check(verifyChecksum(parsed.data, parsed.length, parsed.checksum), "Parsed checksum should verify");
    freeFrame(&parsed);

    frame[0] = 0x00;
    ok = parseFrame(frame, frameLen, &parsed);
    check(!ok, "Bad header should fail parsing");
}

void testBytesToHex() {
    unsigned char data[] = {0x0A, 0x1B, 0xFF};
    char* text = bytesToHex(data, 3);

    check(std::strcmp(text, "0A 1B FF") == 0, "bytesToHex should format bytes");
    delete[] text;
}

void testHistoryList() {
    freeHistory();
    addRecord("Hello", true, false);
    addRecord("Bad", false, true);

    check(g_recordCount == 2, "History count should be 2");
    check(g_historyHead != 0, "History head should not be null");
    check(std::strcmp(g_historyHead->original, "Bad") == 0, "History should use head insertion");
    check(g_historyHead->checksumPassed == false, "History should store checksum result");

    freeHistory();
    check(g_historyHead == 0, "History should be empty after free");
    check(g_recordCount == 0, "History count should reset after free");
}

int main() {
    testXorEncryptRoundTrip();
    testCaesarEncryptRoundTrip();
    testChecksum();
    testBuildAndParseFrame();
    testBytesToHex();
    testHistoryList();

    if (g_failedTests == 0) {
        std::cout << "All tests passed" << std::endl;
        return 0;
    }

    std::cout << g_failedTests << " test(s) failed" << std::endl;
    return 1;
}
