## Trusted Enclave Processor - TEP

This kernel is based of the seL4 microkernel & was written with an AI assistant (Claude). I built this project just for fun to try and recreate Apple's Secure Enclave. It's a dedicated secure subsystem integrated into Apple (SoC). SE is isolated from the main processor to provide an extra layer of security and is designed to keep sensitive user data secure even when the Application Processor kernel becomes compromised. It follows the same design principles as the SoC does — a Boot ROM to establish a hardware root of trust, an AES Engine for efficient and secure cryptographic operations, and protected memory. Although the Secure Enclave doesn’t include storage, it has a mechanism to store information securely on attached storage separate from the NAND flash storage that’s used by the Application Processor and operating system.

<img width="1303" height="1569" alt="image" src="https://github.com/user-attachments/assets/21b5811b-f4b2-45b0-ae46-9357d107f6d2" />
Source: https://support.apple.com/en-gb/guide/security/sec59b0b31ff/web
