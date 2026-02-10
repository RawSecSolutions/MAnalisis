/*
 * wake_scheduler.c - Linux Wake-Up Scheduler
 *
 * Programa para consultar la hora del sistema y programar
 * el encendido (wake-up) del equipo a una hora específica
 * usando el RTC (Real Time Clock) de Linux.
 *
 * Requiere permisos de root para escribir en /sys/class/rtc/rtc0/wakealarm
 *
 * Compilar: gcc -o wake_scheduler wake_scheduler.c
 * Ejecutar: sudo ./wake_scheduler
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define RTC_WAKEALARM_PATH "/sys/class/rtc/rtc0/wakealarm"
#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_BOLD    "\033[1m"

/* ------------------------------------------------------------------ */
/*  Utilidades de tiempo                                               */
/* ------------------------------------------------------------------ */

/* Imprime la hora actual del sistema con formato legible */
static void print_current_time(void)
{
    time_t now = time(NULL);
    struct tm *local = localtime(&now);

    printf("\n" COLOR_CYAN "=== Hora actual del sistema ===" COLOR_RESET "\n");
    printf(COLOR_BOLD "  Fecha : " COLOR_RESET "%04d-%02d-%02d\n",
           local->tm_year + 1900, local->tm_mon + 1, local->tm_mday);
    printf(COLOR_BOLD "  Hora  : " COLOR_RESET "%02d:%02d:%02d\n",
           local->tm_hour, local->tm_min, local->tm_sec);
    printf(COLOR_BOLD "  Zona  : " COLOR_RESET "%s\n", local->tm_zone);
    printf(COLOR_BOLD "  Epoch : " COLOR_RESET "%ld\n", (long)now);
    printf("\n");
}

/* Convierte horas + minutos relativos a un timestamp absoluto */
static time_t relative_to_absolute(int hours, int minutes)
{
    time_t now = time(NULL);
    return now + (hours * 3600) + (minutes * 60);
}

/* Convierte hora:minuto absolutas (hoy o mañana) a timestamp */
static time_t absolute_time_today(int hour, int minute)
{
    time_t now = time(NULL);
    struct tm target;

    localtime_r(&now, &target);
    target.tm_hour = hour;
    target.tm_min  = minute;
    target.tm_sec  = 0;

    time_t result = mktime(&target);

    /* Si la hora ya pasó hoy, programar para mañana */
    if (result <= now) {
        result += 86400;  /* +24 horas */
        printf(COLOR_YELLOW "  (La hora ya pasó hoy, se programará para mañana)\n" COLOR_RESET);
    }

    return result;
}

/* ------------------------------------------------------------------ */
/*  Interacción con el RTC wakealarm                                   */
/* ------------------------------------------------------------------ */

/* Verifica si el archivo wakealarm existe y es accesible */
static int check_rtc_available(void)
{
    if (access(RTC_WAKEALARM_PATH, F_OK) != 0) {
        fprintf(stderr, COLOR_RED "Error: %s no encontrado.\n" COLOR_RESET, RTC_WAKEALARM_PATH);
        fprintf(stderr, "  Tu sistema podría no soportar RTC wakealarm.\n");
        return 0;
    }
    return 1;
}

/* Lee la alarma RTC actualmente configurada (si hay) */
static void show_current_alarm(void)
{
    FILE *fp = fopen(RTC_WAKEALARM_PATH, "r");
    if (!fp) {
        printf(COLOR_YELLOW "  No se pudo leer la alarma actual (¿permisos?).\n" COLOR_RESET);
        return;
    }

    char buf[64] = {0};
    if (fgets(buf, sizeof(buf), fp) && strlen(buf) > 1) {
        long epoch = atol(buf);
        time_t t = (time_t)epoch;
        struct tm *tm_info = localtime(&t);
        printf(COLOR_GREEN "  Alarma activa: " COLOR_RESET "%04d-%02d-%02d %02d:%02d:%02d\n",
               tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
               tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    } else {
        printf("  No hay alarma de wake-up configurada.\n");
    }

    fclose(fp);
}

/* Escribe el timestamp en el wakealarm del RTC */
static int set_wakealarm(time_t wake_time)
{
    /* Primero limpiar la alarma anterior escribiendo "0" */
    FILE *fp = fopen(RTC_WAKEALARM_PATH, "w");
    if (!fp) {
        fprintf(stderr, COLOR_RED "Error al abrir %s: %s\n" COLOR_RESET,
                RTC_WAKEALARM_PATH, strerror(errno));
        fprintf(stderr, "  Asegúrate de ejecutar con: sudo ./wake_scheduler\n");
        return -1;
    }
    fprintf(fp, "0\n");
    fclose(fp);

    /* Ahora escribir la nueva alarma */
    fp = fopen(RTC_WAKEALARM_PATH, "w");
    if (!fp) {
        fprintf(stderr, COLOR_RED "Error al escribir alarma: %s\n" COLOR_RESET, strerror(errno));
        return -1;
    }
    fprintf(fp, "%ld\n", (long)wake_time);
    fclose(fp);

    return 0;
}

/* Cancela la alarma actual */
static int cancel_wakealarm(void)
{
    FILE *fp = fopen(RTC_WAKEALARM_PATH, "w");
    if (!fp) {
        fprintf(stderr, COLOR_RED "Error: %s\n" COLOR_RESET, strerror(errno));
        return -1;
    }
    fprintf(fp, "0\n");
    fclose(fp);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Funciones del menú                                                 */
/* ------------------------------------------------------------------ */

/* Lee un entero del stdin con validación */
static int read_int(const char *prompt, int min, int max)
{
    int value;
    char line[64];

    while (1) {
        printf("%s", prompt);
        if (!fgets(line, sizeof(line), stdin))
            continue;
        if (sscanf(line, "%d", &value) == 1 && value >= min && value <= max)
            return value;
        printf(COLOR_RED "  Valor inválido. Ingresa un número entre %d y %d.\n" COLOR_RESET, min, max);
    }
}

/* Opción 1: Consultar hora del sistema */
static void menu_show_time(void)
{
    print_current_time();
}

/* Opción 2: Programar wake-up con hora absoluta (HH:MM) */
static void menu_set_absolute(void)
{
    printf("\n" COLOR_CYAN "--- Programar encendido a hora específica ---" COLOR_RESET "\n");

    int hour   = read_int("  Hora   (0-23): ", 0, 23);
    int minute = read_int("  Minuto (0-59): ", 0, 59);

    time_t wake = absolute_time_today(hour, minute);
    struct tm *wt = localtime(&wake);

    printf("\n  Se programará wake-up para: " COLOR_GREEN "%04d-%02d-%02d %02d:%02d:%02d" COLOR_RESET "\n",
           wt->tm_year + 1900, wt->tm_mon + 1, wt->tm_mday,
           wt->tm_hour, wt->tm_min, wt->tm_sec);

    /* Mostrar en cuánto tiempo falta */
    time_t now = time(NULL);
    long diff = (long)(wake - now);
    long h = diff / 3600;
    long m = (diff % 3600) / 60;
    printf("  (Faltan %ldh %ldm para el encendido)\n", h, m);

    if (set_wakealarm(wake) == 0)
        printf(COLOR_GREEN "\n  Alarma de wake-up configurada correctamente.\n" COLOR_RESET);
}

/* Opción 3: Programar wake-up en X horas y Y minutos */
static void menu_set_relative(void)
{
    printf("\n" COLOR_CYAN "--- Programar encendido en tiempo relativo ---" COLOR_RESET "\n");

    int hours   = read_int("  En cuántas horas   (0-168): ", 0, 168);
    int minutes = read_int("  En cuántos minutos (0-59) : ", 0, 59);

    if (hours == 0 && minutes == 0) {
        printf(COLOR_RED "  Error: debes indicar al menos 1 minuto.\n" COLOR_RESET);
        return;
    }

    time_t wake = relative_to_absolute(hours, minutes);
    struct tm *wt = localtime(&wake);

    printf("\n  Se programará wake-up para: " COLOR_GREEN "%04d-%02d-%02d %02d:%02d:%02d" COLOR_RESET "\n",
           wt->tm_year + 1900, wt->tm_mon + 1, wt->tm_mday,
           wt->tm_hour, wt->tm_min, wt->tm_sec);

    if (set_wakealarm(wake) == 0)
        printf(COLOR_GREEN "\n  Alarma de wake-up configurada correctamente.\n" COLOR_RESET);
}

/* Opción 4: Ver alarma actual */
static void menu_show_alarm(void)
{
    printf("\n" COLOR_CYAN "--- Estado de la alarma RTC ---" COLOR_RESET "\n");
    show_current_alarm();
    printf("\n");
}

/* Opción 5: Cancelar alarma */
static void menu_cancel_alarm(void)
{
    printf("\n");
    if (cancel_wakealarm() == 0)
        printf(COLOR_GREEN "  Alarma de wake-up cancelada.\n" COLOR_RESET);
    printf("\n");
}

/* Opción 6: Suspender el equipo (suspend-to-RAM) con wake-up programado */
static void menu_suspend_with_wake(void)
{
    printf("\n" COLOR_CYAN "--- Suspender con wake-up ---" COLOR_RESET "\n");
    printf("  Esta opción suspende el equipo (suspend-to-RAM).\n");
    printf("  El equipo se despertará a la hora programada en la alarma RTC.\n\n");

    printf("  Primero, ¿deseas programar una hora de encendido?\n");
    printf("  1) Sí, hora absoluta (HH:MM)\n");
    printf("  2) Sí, en X horas/minutos\n");
    printf("  3) No, ya tengo una alarma configurada\n");
    printf("  0) Cancelar\n");

    int choice = read_int("  Opción: ", 0, 3);

    switch (choice) {
    case 1: menu_set_absolute(); break;
    case 2: menu_set_relative(); break;
    case 3: break;
    case 0: return;
    }

    printf("\n" COLOR_YELLOW "  ¿Confirmar suspensión del equipo? (1=Sí / 0=No): " COLOR_RESET);
    int confirm = read_int("", 0, 1);

    if (confirm == 1) {
        printf("  Suspendiendo equipo...\n");
        int ret = system("systemctl suspend");
        if (ret != 0)
            fprintf(stderr, COLOR_RED "  Error al suspender. ¿Tienes systemd?\n" COLOR_RESET);
    } else {
        printf("  Suspensión cancelada.\n");
    }
}

/* Menú principal */
static void show_menu(void)
{
    printf(COLOR_BOLD "╔══════════════════════════════════════════════╗\n");
    printf("║     Linux Wake-Up Scheduler                  ║\n");
    printf("╚══════════════════════════════════════════════╝\n" COLOR_RESET);
    printf("\n");
    printf("  " COLOR_GREEN "1)" COLOR_RESET " Consultar hora actual del sistema\n");
    printf("  " COLOR_GREEN "2)" COLOR_RESET " Programar encendido a hora específica (HH:MM)\n");
    printf("  " COLOR_GREEN "3)" COLOR_RESET " Programar encendido en X horas/minutos\n");
    printf("  " COLOR_GREEN "4)" COLOR_RESET " Ver alarma de wake-up actual\n");
    printf("  " COLOR_GREEN "5)" COLOR_RESET " Cancelar alarma de wake-up\n");
    printf("  " COLOR_GREEN "6)" COLOR_RESET " Suspender equipo con wake-up programado\n");
    printf("  " COLOR_RED  "0)" COLOR_RESET " Salir\n");
    printf("\n");
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("\n");

    /* Verificar si el RTC está disponible */
    int rtc_ok = check_rtc_available();
    if (!rtc_ok) {
        printf(COLOR_YELLOW "\n  Advertencia: RTC wakealarm no disponible.\n");
        printf("  Podrás consultar la hora pero no programar wake-up.\n" COLOR_RESET);
    }

    /* Verificar permisos de root */
    if (geteuid() != 0) {
        printf(COLOR_YELLOW "\n  Advertencia: No estás ejecutando como root.\n");
        printf("  Para programar wake-up necesitas: sudo ./wake_scheduler\n" COLOR_RESET);
    }

    /* Mostrar hora actual al inicio */
    print_current_time();

    int running = 1;
    while (running) {
        show_menu();

        int choice = read_int("  Selecciona una opción: ", 0, 6);

        switch (choice) {
        case 1: menu_show_time();          break;
        case 2:
            if (rtc_ok) menu_set_absolute();
            else printf(COLOR_RED "  RTC no disponible.\n" COLOR_RESET);
            break;
        case 3:
            if (rtc_ok) menu_set_relative();
            else printf(COLOR_RED "  RTC no disponible.\n" COLOR_RESET);
            break;
        case 4:
            if (rtc_ok) menu_show_alarm();
            else printf(COLOR_RED "  RTC no disponible.\n" COLOR_RESET);
            break;
        case 5:
            if (rtc_ok) menu_cancel_alarm();
            else printf(COLOR_RED "  RTC no disponible.\n" COLOR_RESET);
            break;
        case 6:
            if (rtc_ok) menu_suspend_with_wake();
            else printf(COLOR_RED "  RTC no disponible.\n" COLOR_RESET);
            break;
        case 0:
            printf("\n  Hasta luego.\n\n");
            running = 0;
            break;
        }
    }

    return 0;
}
