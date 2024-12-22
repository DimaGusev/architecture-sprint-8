package com.dgusev.reportsapp;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
public class ReportsController {

    @GetMapping("/reports")
    public Report getReport() {
        return new Report(UUID.randomUUID().toString(), "report content");
    }

    public record Report(String uuid, String payload){}
}
