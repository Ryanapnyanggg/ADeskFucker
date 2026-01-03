#include "process_scanner.h"
#include <iostream>

int main(int argc, char* argv[]) {
    bool debugMode = false;

    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--debug" ||
            std::string(argv[i]) == "-d") {
            debugMode = true;
            break;
        }
    }

    ProcessScanner scanner;

    if (debugMode) {
        scanner.setConsoleVisible(true);
        std::cout << "=== Process Scanner Debug Mode ===" << std::endl;
        std::cout << "Scanning for AnyDesk processes..." << std::endl;
        std::cout << "Press Ctrl+C to exit" << std::endl;
    }
    else {
        scanner.setConsoleVisible(false);
    }

    scanner.scanAndFreezeLoop(1);

    return 0;
}