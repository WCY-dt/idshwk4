@load base/frameworks/sumstats

event http_reply(c:connection, version:string, code:count, reason:string) {
	SumStats::observe("totalresponse",
                      SumStats::Key(),
                      SumStats::Observation($num = 1));
	if(code == 404) {
	    SumStats::observe("badresponse",
                          SumStats::Key(),
                          SumStats::Observation($num = 1));
	    SumStats::observe("badurl",
                          SumStats::Key($host = c$id$resp_h),
                          SumStats::Observation($str = c$http$uri));
	}
}

event zeek_init() {
	local r1 = SumStats::Reducer($stream="totalresponse",$apply=set(SumStats::SUM));
	local r2 = SumStats::Reducer($stream="badresponse",$apply=set(SumStats::SUM));
	local r3 = SumStats::Reducer($stream="badurl",$apply=set(SumStats::UNIQUE));
	SumStats::create([$name = "output_result",
                      $epoch = 10mins,
                      $reducers = set(r1,r2,r3),
                      $epoch_result(ts:time,
                                    key: SumStats::Key,
                                    result: SumStats::Result) = {
		                    local rall = result["totalresponse"];
		                    local rbad = result["badresponse"];
		                    local rurl = result["badurl"];
                            if(rbad$sum > 2 && rbad$sum / rall$sum > 0.2) {
			                    if(rurl$sum / rbad$sum > 0.5) {
				                    print fmt("%s is a scanner with %s scan attemps on %s urls",
                                              key$host,
                                              rbad$num,
                                              rurl$num);
			                    }
		                    }
                      }
    ]);
}