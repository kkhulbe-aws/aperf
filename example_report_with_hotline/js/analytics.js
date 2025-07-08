class Rule {
}
class Rules {
}
class RuleOpts {
}
var Status;
(function (Status) {
    Status["Good"] = "\u2705";
    Status["NotGood"] = "\u274C";
})(Status || (Status = {}));
class Analytics {
}
class Finding {
    constructor(text = '', status = Status.NotGood, recommendation = '') {
        this.text = text;
        this.status = status;
        this.recommendation = recommendation;
    }
    is_good() {
        this.status = Status.Good;
    }
    is_not_good() {
        this.status = Status.NotGood;
    }
}
function is_unique(values_array) {
    return new Set(values_array).size == 1;
}
let all_rules = [
    system_info_rules,
    cpu_utilization_rules,
    perf_stat_rules,
    aperfstats_rules,
    diskstats_rules,
    meminfo_rules,
    netstat_rules,
    vmstat_rules,
];
