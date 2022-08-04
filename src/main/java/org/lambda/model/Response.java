package org.lambda.model;

import java.util.List;

public class Response {

    private String result;

    private String failReason;

    private List<String> offenders;

    private Boolean scoredControl;

    private String description;

    private String controlId;

    public Response(String result,
                    String failReason,
                    List<String> offenders,
                    Boolean scoredControl,
                    String description,
                    String controlId) {
        this.result = result;
        this.failReason = failReason;
        this.offenders = offenders;
        this.scoredControl = scoredControl;
        this.description = description;
        this.controlId = controlId;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public String getFailReason() {
        return failReason;
    }

    public void setFailReason(String failReason) {
        this.failReason = failReason;
    }

    public List<String> getOffenders() {
        return offenders;
    }

    public void setOffenders(List<String> offenders) {
        this.offenders = offenders;
    }

    public Boolean getScoredControl() {
        return scoredControl;
    }

    public void setScoredControl(Boolean scoredControl) {
        this.scoredControl = scoredControl;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getControlId() {
        return controlId;
    }

    public void setControlId(String controlId) {
        this.controlId = controlId;
    }
}
