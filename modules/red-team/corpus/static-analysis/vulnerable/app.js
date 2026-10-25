const lodash = require("lodash");
const source = window.location.hash.slice(1);
document.querySelector("#output").innerHTML = source;
eval(source);
console.log(lodash.camelCase(source));
