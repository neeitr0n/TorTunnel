# TorTunnel

🇬🇧 [English](#english) | 🇷🇺 [Русский](#russian) | 🇨🇳 [中文](#chinese) | 🇮🇷 [فارسی](#persian)

##

## English 🇬🇧

### Description
TorTunnel is a Python utility for routing system traffic through the Tor network using obfs4 bridges. The script automatically configures Tor, manages bridge rotation, monitors connectivity, and applies firewall rules to reduce traffic leaks.

### Features
- Automatic Tor configuration
- obfs4 bridge support
- Automatic bridge rotation
- Connection monitoring and recovery
- IPv6 blocking
- DNS leak protection
- nftables and iptables support
- Automatic cleanup on exit

### Requirements
- Linux
- Python 3
- Tor
- obfs4proxy
- Root privileges (sudo)

### Installation

#### Clone the repository
```bash
git clone https://github.com/neeitr0n/TorTunnel
cd TorTunnel
```

#### Or transfer the project manually
You can copy or move the project directory to another system and run it after installing the required dependencies.

### Usage
```bash
sudo python3 tortunnel.py
```

---

## Русский 🇷🇺

### Описание
TorTunnel — это утилита на Python для маршрутизации системного трафика через сеть Tor с использованием мостов obfs4. Скрипт автоматически настраивает Tor, управляет ротацией мостов, отслеживает соединение и применяет правила межсетевого экрана для уменьшения утечек трафика.

### Возможности
- Автоматическая настройка Tor
- Поддержка мостов obfs4
- Автоматическая ротация мостов
- Мониторинг соединения и восстановление после сбоев
- Блокировка IPv6
- Защита от DNS-утечек
- Поддержка nftables и iptables
- Автоматическая очистка конфигурации при завершении работы

### Требования
- Linux
- Python 3
- Tor
- obfs4proxy
- Права суперпользователя (sudo)

### Установка

#### Клонирование репозитория
```bash
git clone https://github.com/neeitr0n/TorTunnel
cd TorTunnel
```

#### Или перенос проекта вручную
Проект можно скопировать или перенести на другую систему и запустить после установки необходимых зависимостей.

### Использование
```bash
sudo python3 tortunnel.py
```

---

## 中文 🇨🇳

### 描述
TorTunnel 是一个 Python 工具，用于通过 Tor 网络和 obfs4 网桥转发系统流量。脚本能够自动配置 Tor、管理网桥轮换、监控连接状态，并应用防火墙规则以减少流量泄漏。

### 功能
- 自动配置 Tor
- 支持 obfs4 网桥
- 自动轮换网桥
- 连接监控与自动恢复
- 禁用 IPv6
- DNS 泄漏防护
- 支持 nftables 和 iptables
- 退出时自动清理配置

### 系统要求
- Linux
- Python 3
- Tor
- obfs4proxy
- Root 权限（sudo）

### 安装

#### 克隆仓库
```bash
git clone https://github.com/neeitr0n/TorTunnel
cd TorTunnel
```

#### 或手动迁移项目
可以将项目目录复制或移动到其他系统，在安装所需依赖后直接运行。

### 使用方法
```bash
sudo python3 tortunnel.py
```

---

## فارسی🇮🇷

### توضیحات
TorTunnel یک ابزار مبتنی بر Python برای هدایت ترافیک سیستم از طریق شبکه Tor با استفاده از پل‌های obfs4 است. این اسکریپت به‌صورت خودکار Tor را پیکربندی می‌کند، پل‌ها را مدیریت و جایگزین می‌کند، اتصال را پایش می‌کند و قوانین فایروال را برای کاهش نشت ترافیک اعمال می‌کند.

### قابلیت‌ها
- پیکربندی خودکار Tor
- پشتیبانی از پل‌های obfs4
- چرخش خودکار پل‌ها
- پایش اتصال و بازیابی خودکار
- غیرفعال‌سازی IPv6
- محافظت در برابر نشت DNS
- پشتیبانی از nftables و iptables
- پاکسازی خودکار هنگام خروج

### پیش‌نیازها
- Linux
- Python 3
- Tor
- obfs4proxy
- دسترسی Root (sudo)

### نصب

#### کلون کردن مخزن
```bash
git clone https://github.com/neeitr0n/TorTunnel
cd TorTunnel
```

#### یا انتقال دستی پروژه
می‌توانید پوشه پروژه را به سیستم دیگری منتقل یا کپی کنید و پس از نصب وابستگی‌های لازم آن را اجرا نمایید.

### استفاده
```bash
sudo python3 tortunnel.py
```
