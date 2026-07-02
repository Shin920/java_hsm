# Java HSM

Java 기반 HSM(Hardware Security Module) 연동 프로젝트로 Safenet
ProtectToolkit5(PKCS#11)를 이용하여 암호키 생성, 조회, 삭제 및
오프라인/온라인 키 관리 기능을 구현한 프로젝트입니다.

------------------------------------------------------------------------

# 📌 Overview

본 프로젝트는 철도 KMC(Key Management Center) 환경에서 HSM을 활용한 키
관리 기능을 구현하기 위해 개발되었습니다.

## 주요 기능

-   PKCS#11 기반 HSM 연동
-   TCP Server/Client 통신
-   Offline / Online Message 처리
-   Key 생성 / 삭제 / 조회
-   Worker Thread 기반 비동기 처리
-   Queue 기반 이벤트 처리

------------------------------------------------------------------------

# 🏗 System Architecture

``` mermaid
flowchart LR

Client[TCP Client]
Server[TCP Server]
Receiver[EventReceiverThread]
Queue[LinkedBlockingQueue]
Worker[HSMWorkerThread]
Handler[HsmHandler]
Service[HsmService]
PKCS11[Safenet PKCS#11]
HSM[(Hardware Security Module)]

Client --> Server
Server --> Receiver
Receiver --> Queue
Queue --> Worker
Worker --> Handler
Handler --> Service
Service --> PKCS11
PKCS11 --> HSM
```

------------------------------------------------------------------------

# 🔄 Message Flow

``` mermaid
sequenceDiagram

participant Client
participant TCP
participant Receiver
participant Queue
participant Worker
participant HSM

Client->>TCP: Send Request
TCP->>Receiver: Receive Packet
Receiver->>Queue: enqueue()
Worker->>Queue: dequeue()
Worker->>HSM: PKCS#11 Operation
HSM-->>Worker: Result
Worker-->>Client: Response
```

------------------------------------------------------------------------

# 🔐 HSM Key Management

``` mermaid
flowchart TD

Request --> Decision{Operation}

Decision --> Generate
Decision --> Delete
Decision --> Find

Generate --> PKCS11
Delete --> PKCS11
Find --> PKCS11

PKCS11 --> HSM
HSM --> Result
```

------------------------------------------------------------------------

# 📦 Project Structure

``` text
java_hsm
│
├── communication
│   ├── TCP Server
│   └── TCP Client
│
├── thread
│   ├── EventReceiverThread
│   ├── HSMWorkerThread
│   └── Queue
│
├── service
│   ├── HsmService
│   ├── HsmHandler
│   └── DB Service
│
├── codec
│   ├── Encoder
│   └── Decoder
│
├── message
│   ├── Offline
│   └── Online
│
└── config
```

------------------------------------------------------------------------

# 🔐 PKCS#11 Processing

``` mermaid
flowchart TD

Start --> Initialize
Initialize --> OpenSession
OpenSession --> Login
Login --> FindObject
FindObject --> GenerateKey
GenerateKey --> DeleteKey
DeleteKey --> Logout
Logout --> CloseSession
```

------------------------------------------------------------------------

# ⚙ Thread Architecture

``` mermaid
flowchart LR

EventReceiverThread --> LinkedBlockingQueue
LinkedBlockingQueue --> HSMWorkerThread
HSMWorkerThread --> HsmService
HsmService --> PKCS11
PKCS11 --> HardwareHSM
```

------------------------------------------------------------------------

# 🚆 Offline Message Processing

``` mermaid
flowchart LR

InstallTransportKey --> AddAuthenticationKey
AddAuthenticationKey --> ReplaceAllKeys
ReplaceAllKeys --> DeleteKey
DeleteKey --> DeleteAllKeys
DeleteAllKeys --> UpdateValidityPeriod
UpdateValidityPeriod --> Response
```

------------------------------------------------------------------------

# 🛠 Technology Stack

-   Java
-   PKCS#11
-   Safenet ProtectToolkit5
-   TCP/IP
-   LinkedBlockingQueue
-   Multithreading
-   Singleton Pattern

------------------------------------------------------------------------

# ⭐ Technical Highlights

-   PKCS#11 기반 HSM 연동
-   Singleton Session 관리
-   Queue 기반 이벤트 처리
-   Multi Thread Architecture
-   TCP 통신
-   Offline / Online KMC Message 지원
-   Binary Encoder / Decoder
-   철도 KMC 환경 적용

------------------------------------------------------------------------

# 🎯 Development Purpose

본 프로젝트는 철도 KMC 환경에서 안전한 암호키 관리와 HSM 연동을 위해
개발되었습니다.

PKCS#11 표준을 기반으로 키 생성, 삭제 및 조회 기능을 구현하였으며, Queue
기반 Worker Thread 구조를 통해 다수의 요청을 안정적으로 처리할 수 있도록
설계되었습니다.
