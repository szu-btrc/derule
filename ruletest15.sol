pragma solidity ^0.8.0;

contract Ruletest15 {
    string private tupleDescriptor;

    struct ruleStruct{
        string ruleName;
        string[] conditions;
        string action;
        string[] actionArgs;
    }

    struct conditionStruct{
        string conditionName;
        string[] tupleTypes;
        string conditionFunc;
        string[] funcArgs;
    }

    struct tupleStruct{
        string tupleName;
        string tupleType;
        string[] tupleProps;
    }

    //Structrue
    mapping(string => ruleStruct) private ruleSet;
    mapping(string => conditionStruct) private conditionSet;
    mapping(string => tupleStruct) private tupleSet;

    //stateRepository
    mapping(address => uint256) balances;
    mapping(string => string) statePool;
    mapping(string => uint) private assertedTupleIndex;
    string[] private assertedTuple;

    //tmp variable
    bytes private key;
    bytes private value;
    bytes private tmp_tuple;

    uint private tuplecount;
    uint private count;

    string[] private tuplecreated;

    // Event to notify clients
    //event DataChanged(string newData);

    // Function to set the data
    function setTupleDes(string memory newData) public {
        tupleDescriptor = newData;
        //emit DataChanged(newData);
    }

    // Function to get the data
    function getTupleDes() public view returns (string memory) {
        return tupleDescriptor;
    }

    ////Rule
    function createRule(string memory _ruleName, string memory _conditionNames, string memory _actionFunc, string memory _actionArgs) public {
        
        ruleStruct storage newRule = ruleSet[_ruleName];
        
        newRule.ruleName = _ruleName;
        newRule.action = _actionFunc;

        if(newRule.conditions.length>0){
            delete newRule.conditions;
        }
        
        newRule.conditions.push(_conditionNames);
        
        newRule.actionArgs.push(_actionArgs);
        
    }

    function getRule(string memory _ruleName) public view returns (string memory) {
        ruleStruct memory rule = ruleSet[_ruleName];

        string memory conditionstr = getRuleCondition(_ruleName);

        string memory actionargstr = "";

        for(uint i=0;i<rule.actionArgs.length;i++){
            actionargstr = string(abi.encodePacked(actionargstr,rule.actionArgs[i]));

            if(i != rule.actionArgs.length-1){
                actionargstr = string(abi.encodePacked(actionargstr,'&'));
            }
        }
    
        return string(abi.encodePacked(rule.ruleName,'$',conditionstr,'$',rule.action,'$',actionargstr));
    }

    function getRuleCondition(string memory _ruleName) public view returns (string memory){
        ruleStruct memory rule = ruleSet[_ruleName];

        string memory conditionstr = "";

        for(uint i=0;i<rule.conditions.length;i++){

            conditionstr = string(abi.encodePacked(conditionstr,getCondition(rule.conditions[i])));

            if(i != rule.conditions.length-1){
                conditionstr = string(abi.encodePacked(conditionstr,'&'));
            }

        }

        return conditionstr;
    }

    function addCondition(string memory _ruleName, string memory _conditionName) public {
        ruleStruct storage rule = ruleSet[_ruleName];

        rule.conditions.push(_conditionName);
    }

    function addActionArgs(string memory _ruleName, string memory _actionArg) public {
        ruleStruct storage rule = ruleSet[_ruleName];

        rule.actionArgs.push(_actionArg);
    }

    ////Condition
    function createCondition(string memory _conditionName, string memory _tupleType, string memory _conditionFunc, string memory _funcArg) public {
        
        conditionStruct storage newCondition = conditionSet[_conditionName];
        
        newCondition.conditionName = _conditionName;
        newCondition.conditionFunc = _conditionFunc;

        newCondition.tupleTypes.push(_tupleType);
        
        newCondition.funcArgs.push(_funcArg);
    }

    function getCondition(string memory _conditionName) public view returns (string memory){
        conditionStruct memory condition = conditionSet[_conditionName];

        string memory tupleTypesstr = "[";

        for(uint j=0;j<condition.tupleTypes.length;j++){
            tupleTypesstr = string(abi.encodePacked(tupleTypesstr,condition.tupleTypes[j]));

            if(j != condition.tupleTypes.length-1){
                tupleTypesstr = string(abi.encodePacked(tupleTypesstr,','));
            }
        }

        tupleTypesstr = string(abi.encodePacked(tupleTypesstr,']'));

        string memory argsStr = "";

        for(uint j=0;j<condition.funcArgs.length;j++){
            argsStr = string(abi.encodePacked(argsStr,condition.funcArgs[j]));

            if(j != condition.funcArgs.length-1){
                argsStr = string(abi.encodePacked(argsStr,','));
            }
        }

        return string(abi.encodePacked(condition.conditionName,';',tupleTypesstr,';',condition.conditionFunc,';',argsStr));
        
    }

    function addTupleType(string memory _conditionName, string memory _tupleType) public {
        conditionStruct storage condition = conditionSet[_conditionName];

        condition.tupleTypes.push(_tupleType);
    }

    function addFuncArg(string memory _conditionName, string memory _funcArg) public {
        conditionStruct storage condition = conditionSet[_conditionName];

        condition.funcArgs.push(_funcArg);
    }

    //TODO:delete condition

    ////Action
    function updateAction(string memory _ruleName, string memory _actionFunc, string memory _actionArg) public {

        ruleStruct storage rule = ruleSet[_ruleName];
        rule.action = _actionFunc;

        delete rule.actionArgs;

        rule.actionArgs.push(_actionArg);
        
    }

    ////Tuple
    function createTuple(string memory _tupleName, string memory _tupleType, string memory _tupleProp) public {
        tupleStruct storage newTuple = tupleSet[_tupleName];
        
        newTuple.tupleName = _tupleName;
        newTuple.tupleType = _tupleType;

        newTuple.tupleProps.push(_tupleProp);
        
    }

    function addTupleProp(string memory _tupleName, string memory _tupleProp) public {
        tupleStruct storage tuple = tupleSet[_tupleName];

        tuple.tupleProps.push(_tupleProp);
    }

    function getTuple(string memory _tupleName) view public returns (string memory){
        tupleStruct memory tuple = tupleSet[_tupleName];

        string memory tuplePropstr = "";

        for(uint i=0;i<tuple.tupleProps.length;i++){
            tuplePropstr = string(abi.encodePacked(tuplePropstr,tuple.tupleProps[i]));

            if(i != tuple.tupleProps.length-1){
                tuplePropstr = string(abi.encodePacked(tuplePropstr,'$'));
            }
        }

        return string(abi.encodePacked(tuple.tupleName,'$',tuple.tupleType,'$',tuplePropstr));
    }


    ////RE
    function REinitTupleDes() public returns (string memory){

        bool ok = false;
        bytes memory out = "error";

        (ok, out) = address(2).call(abi.encodePacked("1$",tupleDescriptor)); //init tupleDescriptor

        require(ok);

		return string(out);
    }

    function REinitRule(string memory _ruleName) public returns (string memory){

        bool ok = false;
        bytes memory out = "error";

        (ok, out) = address(2).call(abi.encodePacked("2$",getRule(_ruleName))); //init rule

        require(ok);

		return string(out);
    }

    function REstart() public returns (string memory){

        bool ok = false;
        bytes memory out = "error";

        (ok, out) = address(2).call(abi.encodePacked("3")); 

        require(ok);

		return string(out);
    }

    function REsyncTuples() public returns (string memory){
        bool ok = false;
        bytes memory out = "error";

        for(uint i=0;i<assertedTuple.length;i++){
            (ok, out) = address(2).call(abi.encodePacked("8$##",uintToString(i),'$',getTuple(assertedTuple[i]))); 
            require(ok);
        }

        out = "sync Tuples successfully";

        return string(out);
    }

    function REassertTuple(string memory str) public {
        count++;
    }

    function REassertTuple2(string memory _tupleName) public returns (string memory){


        bool ok = false;
        bytes memory out = "error";

        if(assertedTupleIndex[_tupleName] != 0){
            return string("tuple existed");
        }

        assertedTuple.push(_tupleName);
        assertedTupleIndex[_tupleName] = assertedTuple.length;

        tuplecount++;

        (ok, out) = address(2).call(abi.encodePacked("4$#",uintToString(tuplecount),'$',getTuple(_tupleName))); 

        require(ok);

        parse(out);

        (ok, out) = address(2).call("9");

        require(ok);

		return string(out);
    }

    function REretractTuple(string memory _tupleName) public returns (string memory){

        bool ok = false;
        bytes memory out = "error";

        removet(_tupleName);

        (ok, out) = address(2).call(abi.encodePacked("5$",_tupleName)); 

        require(ok);

		return string(out);
    }

    function REdeleteRule(string memory _ruleName) public returns (string memory){

        bool ok = false;
        bytes memory out = "error";

        delete ruleSet[_ruleName];

        (ok, out) = address(2).call(abi.encodePacked("6$",_ruleName)); 

        require(ok);

		return string(out);
    }

    function REclose() public returns (string memory){

        bool ok = false;
        bytes memory out = "error";

        (ok, out) = address(2).call(abi.encodePacked("7")); 

        require(ok);

		return string(out);
    }

    //key1:value1&key2:value2$t1&t2&t3
    function parse(bytes memory input) public{

        if(input.length <= 1) return;

        bool iskey = true;
        bool tuplePart = false;
        delete key;
        delete value;
        delete tmp_tuple;

        for(uint i=0;i<input.length;i++){
            if(tuplePart){
                if(input[i] == '&'){
                    removet(string(tmp_tuple));
                    delete tmp_tuple;
                }else{
                    tmp_tuple.push(input[i]);
                }
            }else{
                if(input[i] == ':'){
                    iskey = false;
                }else if(input[i] == '&'){
                    iskey = true;
                    statePool[string(key)]=string(value);
                    delete key;
                    delete value;
                }else if(input[i] == '$'){
                    tuplePart = true;
                    if(i==0) continue;
                    statePool[string(key)]=string(value);
                    delete key;
                    delete value;
                }else if(iskey){
                    key.push(input[i]);
                }else{
                    value.push(input[i]);
                }
            }
        }

        if(input[input.length-1] == '$'){
            return;
        }else if(tuplePart){
            removet(string(tmp_tuple));
            delete tmp_tuple;
        }else{
            statePool[string(key)] = string(value);
            delete key;
            delete value;
        }

    }


    // 删除指定元素
    function removet(string memory tuple) private {

        uint index = assertedTupleIndex[tuple];

        if(index == 0){
            return;
        }

        index = index-1;

        delete assertedTupleIndex[tuple];

        //require(index < assertedTuple.length, "Index out of bounds");

        // 将要删除的元素与数组中最后一个元素交换
        assertedTuple[index] = assertedTuple[assertedTuple.length - 1];

        // 移除最后一个元素（即原来要删除的元素）
        assertedTuple.pop();

        if(index<assertedTuple.length){
            assertedTupleIndex[assertedTuple[index]] = index+1;
        }

    }

    function uintToString(uint _i) private pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (_i != 0) {
            k = k-1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }

    function addbl(address _add, uint _value) public {
        balances[_add] += _value;
    }

    //Test Utils
    function getBalance(address _add) public view returns (uint) {
        return balances[_add];
    }

    function setbl(address _add, uint _value) public {
        balances[_add] = _value;
    }

    function getkv(string memory _key) public view returns (string memory) {
        return statePool[_key];
    }

    function setkv(string memory _key, string memory _value) public {
        statePool[_key] = _value;
    }
    
    function addtuple(string memory tuple) public {
        assertedTuple.push(tuple);
        assertedTupleIndex[tuple] = assertedTuple.length;
    }

    function gettuplelist() public view returns (string memory){
        string memory res = "";
        for(uint i=0;i<assertedTuple.length;i++){
            res = string(abi.encodePacked(res,assertedTuple[i],'$'));
        }
        return res;
    }

    function gettupleindex(string memory _key) public view returns (uint) {
        return assertedTupleIndex[_key];
    }

    //Experiment
    function tuplerefresh() public {
        delete tuplecreated;
    }

    function gettuplecreated(uint i) public view returns (string memory) {
        return tuplecreated[i];
    }

    function tupleregister(string memory _str) public {
        tuplecreated.push(_str);
    }

    function tuplecreator(string memory _tupleName, string memory _tupleType, uint _num) public {

        createTuple(_tupleName, _tupleType, tuplecreated[0]);

        uint len = tuplecreated.length;

        for(uint i=1; i<_num; i++){
            addTupleProp(_tupleName, tuplecreated[i%len]);
        }
    }

    function tupleproducer(string memory _tupleType, uint _num) public {

        uint len = tuplecreated.length;

        for(uint i=0; i<_num; i++){
            string memory tupleName = string(abi.encodePacked(tuplecreated[i%len],uintToString(i)));
            createTuple(tupleName, _tupleType, "testprop");
        }

    }

    function batchassert(uint _num) public {
         uint len = tuplecreated.length;

        for(uint i=0; i<_num; i++){
            string memory tupleName = string(abi.encodePacked(tuplecreated[i%len],uintToString(i)));
            REassertTuple(tupleName);
        }
    }

    function parsetest(string memory strs) public {

        bytes memory input = bytes(strs);

        (bool ok, bytes memory out) = address(3).call("");

        parse(input);

        (ok, out) = address(4).call("");
    }

}