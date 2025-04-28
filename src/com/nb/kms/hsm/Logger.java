package com.nb.kms.hsm;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Logger {
    private static final DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");

    public static void log(String level, String message) {
        System.out.println("[" + dtf.format(LocalDateTime.now()) + "][" + level + "] " + message);
    }

    public static void error(String message, Throwable t) {
        System.err.println(("[" + dtf.format(LocalDateTime.now()) + "][ERROR] " + message));
        t.printStackTrace(System.out);
    }
    public static void error(String message) {
        System.err.println("[" + dtf.format(LocalDateTime.now()) + "][ERROR] " + message);
    }
}