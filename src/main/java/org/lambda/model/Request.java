package org.lambda.model;

public class Request {

    public String scanId;

    private String accountId;

    public Request() {
    }

    public Request(String scanId, String accountId) {
        this.scanId = scanId;
        this.accountId = accountId;
    }

    public String getScanId() {
        return scanId;
    }

    public void setScanId(String scanId) {
        this.scanId = scanId;
    }

    public String getAccountId() {
        return accountId;
    }

    public void setAccountId(String accountId) {
        this.accountId = accountId;
    }

}
