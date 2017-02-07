$(document).ready(function(){

	$('#tabs li').click(function(){
		//clear fields
		$("#search .text").val("");
		//clear results
		$("#results").html("");
		//tabs
		var id_org = event.target.id;
		var id = id_org.replace("tab_", "");
		$("#tabs li").removeClass("tab_selected");
		$("#"+id_org).addClass("tab_selected");
		//search containers
		$(".search_cont").hide();
		$("#search_cont_"+id).fadeIn();
	});

	$('#submit_new').click(function(){
		var new_institution = $("#new_institution").val();
		var new_orcid = $("#new_orcid").val().replace(" ","");
		var researchers = new_orcid.split(",");
		var params = "institution="+new_institution+"&researchers="+researchers;

		//json
		$.ajax({
		  	type:"POST",
		  	data:params,
		  	contentType:"application/json",
	  		crossDomain:true
		}).done(function(data){
			$("#search_cont_new p").html("Congratulations, you've just created a new RAiD!");
			$("#new_institution").val("");
			$("#new_orcid").val("");
			$("#results").html(JSON.stringify(data, null, 4));
		});
	});

	$('#submit_update').click(function(){
		var new_institution = $("#new_institution").val();
		var new_orcid = $("#new_orcid").val().replace(" ","");
		var researchers = new_orcid.split(",");
		var params = "institution="+new_institution+"&researchers="+researchers;

		//json
		$.ajax({
		  	type:"POST",
		  	data:params,
		  	contentType:"application/json",
	  		crossDomain:true
		}).done(function(data){
			$("#search_cont_update p").html("Congratulations, you've just updated your RAiD!");
			$("#new_institution").val("");
			$("#new_orcid").val("");
			$("#results").html(JSON.stringify(data, null, 4));
		});
	});


	$('#submit_search').click(function(){
		//loader
		$("#results").html("<div id='loading'>Loading</div>");

		//json
		$.ajax({
		  	type:"GET",
	  		crossDomain:true
		}).done(function(data){

			//vars
			var keyword = $("#search_keyword").val().toLowerCase();
			var researcher = $("#search_researcher").val().toLowerCase();
			var orcid = $("#search_orcid").val().toLowerCase();
			var activityid = $("#search_activityid").val().toLowerCase();
			var org = $("#search_organisation").val().toLowerCase();

			//get results			
			var count = data.length;
			var results = [];
			for(var i=0; i<count; i++){

				//reset
				var match = 0;
				var match_keyword = 0;
				var match_researcher = 0;
				var match_orcid = 0;
				var match_activityid = 0;
				var match_org = 0;

				//keyword
				if(keyword!=""){
					//grid
					var loop_grid = data[i]["grid"].toLowerCase();
					var n = loop_grid.indexOf(keyword);
					if(n>-1){match_keyword=1;}
					//instition
					var loop_org = data[i]["institution"].toLowerCase();
					var n = loop_org.indexOf(keyword);
					if(n>-1){match_keyword=1;}
					//owner
					var loop_owner = data[i]["owner"].toLowerCase();
					var n = loop_owner.indexOf(keyword);
					if(n>-1){match_keyword=1;}
					//researcher, orcid
					var cnt_researchers = data[i]["researchers"].length;
					for(var r=0; r<cnt_researchers; r++){
						//researcher
						var loop_researcher = data[i]["researchers"][r]["displayName"].toLowerCase();
						var n = loop_researcher.indexOf(keyword);
						if(n>-1){match_keyword=1;}
						//orcid
						var loop_orcid = data[i]["researchers"][r]["orcid"];
						var n = loop_orcid.indexOf(keyword);
						if(n>-1){match_keyword=1;}
					}
				}

				//researcher orcid
				if(researcher!="" || orcid!=""){
					var cnt_researchers = data[i]["researchers"].length;
					for(var r=0; r<cnt_researchers; r++){
						//researcher
						var loop_researcher = data[i]["researchers"][r]["displayName"].toLowerCase();
						var n = loop_researcher.indexOf(researcher);
						if(n>-1){match_researcher=1;}
						//orcid
						var loop_orcid = data[i]["researchers"][r]["orcid"];
						if(orcid==loop_orcid){
							match_orcid=1;
						}
					}
				}

				//activity id
				if(activityid!=""){
					var loop_activityid = data[i]["id"];
					if(activityid==loop_activityid){
						match_activityid=1;
					}
				}

				//institution
				if(org!=""){
					var loop_org = data[i]["institution"].toLowerCase();
					var n = loop_org.indexOf(org);
					if(n>-1){match_org=1;}
				}

				//check matches
				if(match_keyword==1 || match_researcher==1 || match_orcid==1 || match_activityid==1 || match_org==1){
					if(keyword!=""){
						if(match_keyword==1){match=1;}else{match=2;}
					}
					if(researcher!=""){
						if(match_researcher==1){
							if(match!=2){match=1;} else {match=2;}
						} else {
							match=2;
						}
					}
					if(orcid!=""){
						if(match_orcid==1){
							if(match!=2){match=1;} else {match=2;}
						} else {
							match=2;
						}
					}
					if(activityid!=""){
						if(match_activityid==1){
							if(match!=2){match=1;} else {match=2;}
						} else {
							match=2;
						}
					}
					if(org!=""){
						if(match_org==1){
							if(match!=2){match=1;} else {match=2;}
						} else {
							match=2;
						}
					}
					if(match==1){
						results.push(i);
					}
				}
			}		

			//print results
			var cnt = results.length;
			if(cnt>0){
				$("#results").html("<p>Showing results <strong>1 - "+cnt+"</strong> of <strong>"+cnt+" results.</p>");
				for(var x=0; x<cnt; x++){
					var id = results[x];
					var activityid = data[id]["id"];
					var institution = data[id]["institution"];
					var purl = data[id]["purl"];
					var grid = data[id]["grid"];
					var owner = data[id]["owner"];

					var researchers = "";
					var cnt_researchers = data[id]["researchers"].length;
					var orcids = "";
					for(var r=0; r<cnt_researchers; r++){
						researchers += data[id]["researchers"][r]["displayName"]+" ("+data[id]["researchers"][r]["orcid"]+"), ";
						orcids += data[id]["researchers"][r]["orcid"]+", ";
					}
					researchers = researchers.substring(0,researchers.length-2);
					orcids = orcids.substring(0,orcids.length-2);

					$("#results").append("<div class='result'><a onclick='update_this("+"\""+activityid+"\""+","+"\""+institution+"\""+","+"\""+orcids+"\""+");' class='purl'>"+activityid+" - "+institution+"</a><p><strong>Owner: </strong><span>"+owner+"</span><strong>GRID: </strong><span>"+grid+"</span></p><p><strong>Researchers: </strong>"+researchers+"</p></div>");
				}
			} else {
				$("#results").html("<p>Sorry we could not find any results for your search. Please try again.</p>");
			}
		});
	});
});

$(document).keyup(function(e) {
  if(e.keyCode==13){ 
    if ($("#submit_new").is(":visible")){
    	$("#submit_new").trigger("click");
    } else if ($("#submit_update").is(":visible")){
    	$("#submit_update").trigger("click");
    } else if($("#submit_search").is(":visible")){
        $("#submit_search").trigger("click");
    }
  }
});

function update_this(activityid,institution,orcids){
	//clear results
	$("#results").html("");
	//tabs
	$("#tabs li").removeClass("tab_selected");
	$("#tab_update").addClass("tab_selected");
	//search containers
	$(".search_cont").hide();
	$("#search_cont_search").hide();
	$("#search_cont_update").fadeIn();
	//assign variables
	$("#update_activity_id").val(activityid);
	$("#update_institution").val(institution);
	$("#update_orcid").val(orcids);
}
















