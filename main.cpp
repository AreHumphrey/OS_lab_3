#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
    #include <windows.h>
    #include <process.h>
    #define getpid _getpid
#else
    #include <unistd.h>
    #include <sys/mman.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <semaphore.h>
    #include <sys/wait.h>
#endif

#ifdef _WIN32
    using ProcessId = DWORD;
    const char* SHM_NAME = "Global\\Lab3SharedMemory";
    const char* MUTEX_NAME = "Global\\Lab3Mutex";
    const char* LOG_FILENAME = "lab3_shared.log";
#else
    using ProcessId = pid_t;
    const char* SHM_NAME = "/lab3_shared_memory";
    const char* MUTEX_NAME = "/lab3_mutex";
    const char* LOG_FILENAME = "lab3_shared.log";
#endif

struct SharedData {
    int counter;
    bool child1_running;
    bool child2_running;
    ProcessId child1_pid;
    ProcessId child2_pid;
    bool is_master;
    ProcessId master_pid;
};

SharedData* shared = nullptr;
std::atomic<bool> running{true};
std::mutex input_mutex;
std::string input_command;
std::atomic<bool> has_input{false};

#ifdef _WIN32
HANDLE shm_handle = nullptr;
HANDLE mutex_handle = nullptr;
#else
int shm_fd = -1;
sem_t* mutex_sem = nullptr;
#endif

std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::time_t time_now = std::chrono::system_clock::to_time_t(now);
    std::tm* tm_now = std::localtime(&time_now);
    
    std::ostringstream oss;
    oss << std::put_time(tm_now, "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

void log_message(const std::string& message) {
    std::ofstream log(LOG_FILENAME, std::ios::app);
    if (log.is_open()) {
        std::string log_msg = "[" + get_timestamp() + "] [PID=" + std::to_string(getpid()) + "] " + message;
        log << log_msg << std::endl;
        log.flush();
        std::cout << log_msg << std::endl;
    }
}

void sleep_ms(int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
#endif
}

bool init_shared_memory(bool create_new) {
#ifdef _WIN32
    shm_handle = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        0,
        sizeof(SharedData),
        SHM_NAME
    );
    
    if (shm_handle == nullptr) {
        std::cerr << "Ошибка создания разделяемой памяти" << std::endl;
        return false;
    }
    
    bool first_instance = (GetLastError() != ERROR_ALREADY_EXISTS);
    shared = (SharedData*)MapViewOfFile(shm_handle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedData));
    
    if (shared == nullptr) {
        CloseHandle(shm_handle);
        std::cerr << "Ошибка отображения памяти" << std::endl;
        return false;
    }
    
    if (first_instance && create_new) {
        ZeroMemory(shared, sizeof(SharedData));
        shared->counter = 0;
        shared->is_master = true;
        shared->master_pid = getpid();
        log_message("Создан новый экземпляр разделяемой памяти");
    } else {
        shared->is_master = (getpid() == shared->master_pid);
        log_message("Подключен к существующей разделяемой памяти");
    }
    
    mutex_handle = CreateMutexA(nullptr, FALSE, MUTEX_NAME);
    if (mutex_handle == nullptr) {
        UnmapViewOfFile(shared);
        CloseHandle(shm_handle);
        std::cerr << "Ошибка создания мьютекса" << std::endl;
        return false;
    }
    
    return true;
    
#else
    shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        std::cerr << "Ошибка создания разделяемой памяти" << std::endl;
        return false;
    }
    
    if (create_new) {
        if (ftruncate(shm_fd, sizeof(SharedData)) == -1) {
            close(shm_fd);
            shm_unlink(SHM_NAME);
            std::cerr << "Ошибка выделения памяти" << std::endl;
            return false;
        }
    }
    
    shared = (SharedData*)mmap(nullptr, sizeof(SharedData), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shared == MAP_FAILED) {
        close(shm_fd);
        shm_unlink(SHM_NAME);
        std::cerr << "Ошибка отображения памяти" << std::endl;
        return false;
    }
    
    if (create_new) {
        memset(shared, 0, sizeof(SharedData));
        shared->counter = 0;
        shared->is_master = true;
        shared->master_pid = getpid();
        log_message("Создан новый экземпляр разделяемой памяти");
    } else {
        shared->is_master = (getpid() == shared->master_pid);
        log_message("Подключен к существующей разделяемой памяти");
    }
    
    mutex_sem = sem_open(MUTEX_NAME, O_CREAT, 0666, 1);
    if (mutex_sem == SEM_FAILED) {
        munmap(shared, sizeof(SharedData));
        close(shm_fd);
        std::cerr << "Ошибка создания мьютекса" << std::endl;
        return false;
    }
    
    return true;
#endif
}

void lock_shared() {
#ifdef _WIN32
    WaitForSingleObject(mutex_handle, INFINITE);
#else
    sem_wait(mutex_sem);
#endif
}

void unlock_shared() {
#ifdef _WIN32
    ReleaseMutex(mutex_handle);
#else
    sem_post(mutex_sem);
#endif
}

bool launch_child(int mode) {
    log_message("Попытка запуска копии " + std::to_string(mode));
    
#ifdef _WIN32
    char buffer[1024];
    GetModuleFileNameA(nullptr, buffer, sizeof(buffer));
    
    std::string cmd = std::string(buffer) + " " + std::to_string(mode);
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    if (!CreateProcessA(
        nullptr,
        (LPSTR)cmd.c_str(),
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi
    )) {
        log_message("Ошибка запуска копии " + std::to_string(mode));
        return false;
    }
    
    CloseHandle(pi.hThread);
    
    lock_shared();
    if (mode == 1) {
        shared->child1_pid = pi.dwProcessId;
        shared->child1_running = true;
    } else {
        shared->child2_pid = pi.dwProcessId;
        shared->child2_running = true;
    }
    unlock_shared();
    
    log_message("Запущена копия " + std::to_string(mode) + " (PID: " + std::to_string(pi.dwProcessId) + ")");
    return true;
    
#else
    pid_t pid = fork();
    if (pid < 0) {
        log_message("Ошибка fork для копии " + std::to_string(mode));
        return false;
    } else if (pid == 0) {
        execl("/proc/self/exe", "/proc/self/exe", std::to_string(mode).c_str(), nullptr);
        log_message("Ошибка execl для копии " + std::to_string(mode));
        _exit(1);
    } else {
        lock_shared();
        if (mode == 1) {
            shared->child1_pid = pid;
            shared->child1_running = true;
        } else {
            shared->child2_pid = pid;
            shared->child2_running = true;
        }
        unlock_shared();
        log_message("Запущена копия " + std::to_string(mode) + " (PID: " + std::to_string(pid) + ")");
        return true;
    }
#endif
}

void check_child_completion(int mode) {
    lock_shared();
    bool* running_flag = (mode == 1) ? &shared->child1_running : &shared->child2_running;
    ProcessId pid = (mode == 1) ? shared->child1_pid : shared->child2_pid;
    unlock_shared();
    
    if (!*running_flag || pid == 0) return;
    
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess != nullptr) {
        DWORD exit_code;
        if (GetExitCodeProcess(hProcess, &exit_code) && exit_code != STILL_ACTIVE) {
            lock_shared();
            *running_flag = false;
            unlock_shared();
            CloseHandle(hProcess);
        } else {
            CloseHandle(hProcess);
        }
    }
#else
    int status;
    pid_t result = waitpid(pid, &status, WNOHANG);
    if (result == pid) {
        lock_shared();
        *running_flag = false;
        unlock_shared();
    }
#endif
}

void signal_handler(int signal) {
    running = false;
    log_message("Получен сигнал завершения");
}

void input_thread() {
    std::string line;
    while (running) {
        if (std::getline(std::cin, line)) {
            if (!line.empty()) {
                std::lock_guard<std::mutex> lock(input_mutex);
                input_command = line;
                has_input = true;
            }
        }
 
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void run(int child_mode = 0) {
    log_message("Процесс запущен (режим: " + std::to_string(child_mode) + ")");
    
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
#ifndef _WIN32
    std::signal(SIGQUIT, signal_handler);
#endif
    
    bool is_first = (child_mode == 0);
    if (!init_shared_memory(is_first)) {
        log_message("Не удалось инициализировать разделяемую память");
        return;
    }
    
    if (child_mode == 1) {
        log_message("Копия 1: начинаю работу");
        
        lock_shared();
        int old_value = shared->counter;
        shared->counter += 10;
        int new_value = shared->counter;
        unlock_shared();
        
        log_message("Копия 1: счётчик изменён с " + std::to_string(old_value) + " на " + std::to_string(new_value));
        log_message("Копия 1: завершаю работу");
        return;
    }
    
    if (child_mode == 2) {
        log_message("Копия 2: начинаю работу");
        
        lock_shared();
        int old_value = shared->counter;
        shared->counter *= 2;
        int doubled = shared->counter;
        unlock_shared();
        
        log_message("Копия 2: счётчик удвоен с " + std::to_string(old_value) + " до " + std::to_string(doubled));
        
        sleep_ms(2000);
        
        lock_shared();
        shared->counter /= 2;
        int halved = shared->counter;
        unlock_shared();
        
        log_message("Копия 2: счётчик уменьшен вдвое до " + std::to_string(halved));
        log_message("Копия 2: завершаю работу");
        return;
    }
    

    std::thread input_th(input_thread);
    
    auto last_increment = std::chrono::steady_clock::now();
    auto last_log = std::chrono::steady_clock::now();
    auto last_child_launch = std::chrono::steady_clock::now();
    
    while (running) {
        auto now = std::chrono::steady_clock::now();
        

        if (has_input.exchange(false)) {
            std::lock_guard<std::mutex> lock(input_mutex);
            try {
        
                std::istringstream iss(input_command);
                std::string first_word;
                iss >> first_word;
                
                int new_value;
                if (first_word == "set") {
                    iss >> new_value;
                } else {
                
                    new_value = std::stoi(first_word);
                }
                
                lock_shared();
                int old_value = shared->counter;
                shared->counter = new_value;
                unlock_shared();
                log_message("Пользователь установил счётчик: " + std::to_string(old_value) + " -> " + std::to_string(new_value));
            } catch (...) {
                log_message("Ошибка: введите число или 'set <число>'");
            }
        }
        
 
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_increment).count() >= 300) {
            lock_shared();
            shared->counter++;
            int current_value = shared->counter;
            unlock_shared();
            
            log_message("Счётчик увеличен до: " + std::to_string(current_value));
            last_increment = now;
        }
        
  
        lock_shared();
        bool is_master = shared->is_master;
        int counter_value = shared->counter;
        unlock_shared();
        
        if (is_master && std::chrono::duration_cast<std::chrono::milliseconds>(now - last_log).count() >= 1000) {
            log_message("Счётчик = " + std::to_string(counter_value));
            last_log = now;
        }
        

        if (is_master && std::chrono::duration_cast<std::chrono::milliseconds>(now - last_child_launch).count() >= 3000) {
            check_child_completion(1);
            check_child_completion(2);
            
            lock_shared();
            bool child1_busy = shared->child1_running;
            bool child2_busy = shared->child2_running;
            unlock_shared();
            
            if (child1_busy || child2_busy) {
                log_message("Предыдущие копии ещё работают, запуск новых отложен");
            } else {
                log_message("Запуск копий...");
                if (!launch_child(1)) {
                    log_message("Ошибка запуска копии 1");
                }
                if (!launch_child(2)) {
                    log_message("Ошибка запуска копии 2");
                }
            }
            last_child_launch = now;
        }
        
        sleep_ms(10);
    }
    
    input_th.join();
    
#ifdef _WIN32
    if (shared) UnmapViewOfFile(shared);
    if (shm_handle) CloseHandle(shm_handle);
    if (mutex_handle) CloseHandle(mutex_handle);
#else
    if (shared) munmap(shared, sizeof(SharedData));
    if (shm_fd >= 0) close(shm_fd);
    if (mutex_sem) sem_close(mutex_sem);
    if (is_first) {
        shm_unlink(SHM_NAME);
        sem_unlink(MUTEX_NAME);
    }
#endif
    
    log_message("Процесс завершён");
}

int main(int argc, char* argv[]) {
    int child_mode = 0;
    
    if (argc > 1) {
        try {
            child_mode = std::stoi(argv[1]);
            if (child_mode < 1 || child_mode > 2) child_mode = 0;
        } catch (...) {
            child_mode = 0;
        }
    }
    
    run(child_mode);
    return 0;
}
