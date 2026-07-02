# Java HSM Integration Framework

Java 기반 HSM(Hardware Security Module) 연동 프레임워크입니다.

Safenet ProtectToolkit5(PKCS#11)를 이용하여 HSM과 연동하며, TCP 기반
메시지 처리, 키 생성/조회/삭제, 암호화 연산 및 철도 KMC(Key Management
Center) 메시지 처리를 지원합니다.

------------------------------------------------------------------------

## 📌 Overview

본 프로젝트는 HSM 장비와 애플리케이션 사이의 인터페이스를 제공하기 위해
개발되었습니다.

주요 목적

-   PKCS#11 기반 HSM 연동
-   DES/2DES/3DES/RSA 키 관리
-   TCP 기반 HSM 요청 처리
-   작업 큐 기반 비동기 처리
-   철도 KMC Offline/Online 메시지 인코딩 및 디코딩
-   CBC-MAC 검증

------------------------------------------------------------------------

## 🚀 Key Features

### HSM Session Management

-   PKCS#11 Session 생성
-   Login / Logout
-   Token 연결
-   Slot 관리
-   Singleton 기반 Session 유지

### Key Management

지원 기능

-   Generate Key
-   Delete Key
-   Find Key
-   Get Key Handle
-   Get KCV
-   Encrypt / Decrypt

### TCP Communication

-   TCP Server
-   TCP Client
-   Object Stream 기반 메시지 송수신
-   Event 기반 처리

### Worker Queue

LinkedBlockingQueue 기반 구조를 사용하여 HSM 요청을 순차적으로
처리합니다.

구성

-   EventReceiverThread
-   HSMWorkerThread
-   HsmHandler

### PKCS#11 Integration

Safenet ProtectToolkit5 라이브러리를 이용하여

-   C_Initialize
-   C_OpenSession
-   C_Login
-   C_FindObjects
-   C_GenerateKey
-   C_DestroyObject

등 주요 API를 호출합니다.

### Railway KMC Message

철도 KMC 규격 메시지를 지원합니다.

Offline

-   AddAuthenticationKey
-   DeleteKey
-   ReplaceAllKeys
-   InstallTransportKey
-   UpdateKeyValidityPeriod

Online

-   AddKey
-   DeleteAllKeys

### Message Codec

Encoder / Decoder 구현

-   Offline Encoder
-   Offline Decoder
-   Packet Utility
-   Codec Utility

### CBC-MAC Test

Triple DES CBC-MAC 검증 예제를 제공합니다.

------------------------------------------------------------------------

## 📁 Project Structure

``` text
src
│
├── Threads
│   ├── EventReceiverThread
│   └── HSMWorkerThread
│
├── Message
│   ├── offline
│   ├── online
│   └── constant
│
├── codec
│   ├── offlineEntity
│   └── offlineKmc
│
├── communication
│   ├── tcp
│   └── packet
│
├── com.nb.kms.hsm
│
├── config
│
└── singleton
```

------------------------------------------------------------------------

## 🏗 Architecture

``` text
TCP Client
      │
      ▼
EventReceiverThread
      │
      ▼
LinkedBlockingQueue
      │
      ▼
HSMWorkerThread
      │
      ▼
HsmHandler
      │
      ▼
Safenet PKCS#11
      │
      ▼
Hardware Security Module
```

------------------------------------------------------------------------

## 📚 Main Components

### HsmHandler

애플리케이션의 핵심 클래스입니다.

-   Session 관리
-   Worker 초기화
-   Queue 관리

### EventReceiverThread

TCP 요청을 수신하여 Queue에 저장합니다.

### HSMWorkerThread

Queue의 작업을 순차적으로 처리하며 HSM API를 호출합니다.

### HsmService

PKCS#11 연동 기능을 제공합니다.

### HsmMsg

HSM 요청 및 응답 메시지 객체입니다.

### communication

TCP 통신 및 Packet 처리를 담당합니다.

### codec

KMC 메시지 Encoding / Decoding을 담당합니다.

------------------------------------------------------------------------

## 🛠 Technologies

-   Java
-   PKCS#11
-   Safenet ProtectToolkit5
-   TCP Socket
-   LinkedBlockingQueue
-   Multi Thread
-   Singleton Pattern
-   Binary Protocol
-   Triple DES
-   RSA

------------------------------------------------------------------------

## ⭐ Technical Highlights

-   PKCS#11 기반 HSM 연동
-   Thread-safe Queue 처리
-   Singleton Session 관리
-   TCP 기반 HSM Server
-   Binary Message Encoding / Decoding
-   Railway KMC Protocol 지원
-   CBC-MAC 검증 예제
-   Offline / Online Key Management

------------------------------------------------------------------------

## 🎯 Development Purpose

본 프로젝트는 철도 보안 키 관리 시스템(KMC)과 HSM 간의 연동을 위해
개발되었습니다.

PKCS#11 표준을 이용하여 HSM의 키 생성 및 관리 기능을 제공하며, TCP 기반
메시지 처리 구조와 작업 큐를 이용하여 안정적인 요청 처리를
구현하였습니다. 또한 철도 KMC 규격의 Offline/Online 메시지 처리 기능과
CBC-MAC 검증 예제를 포함하여 실제 시스템 개발 및 시험 환경에서 활용할 수
있도록 설계되었습니다.
