var yargs = require('yargs');
var url = require('url');
var restify = require('restify');
var loki = require('lokijs');
var passport = require('passport-restify');
var Strategy = require('passport-oauth2-jwt-bearer').Strategy;
var bunyan = require('bunyan');

// Parse Arguments
var argv = yargs
.usage('\nLaunches the ICE Resource Server\n\n' +
'Usage:\n\t$0 -iss {issuer} -aud {audience}', {
  issuer: {
    description: 'Issuer URI for Authorization Server',
    required: true,
    alias: 'iss',
    string: true
  },
  audience: {
    description: 'Audience URI for Resource Server',
    required: true,
    alias: 'aud',
    default: 'http://api.example.com',
    string: true
  }
})
.example('\t$0 --aud https://example.okta.com/as/aus7xbiefo72YS2QW0h7 --aud http://api.example.com', '')
.argv;


//Globals
var log = new bunyan.createLogger({name: 'ice-resource-server'});

var strategy = new Strategy(
  {
    audience: argv.audience,
    issuer: argv.issuer,
    metadataUrl: argv.issuer + '/.well-known/oauth-authorization-server',
    loggingLevel: 'debug'
  }, function(token, done) {
    return done(null, token);
  });

var server = restify.createServer(
  {
    log: log,
    serializers: restify.bunyan.serializers
  });

//In-memory DB
var db = new loki('ice');
var promos = db.addCollection('promos', {unique: 'code'});

//Middleware Configuration
server.use(restify.requestLogger());
server.use(restify.bodyParser());
server.use(passport.initialize());
passport.use(strategy);

//Add CORS Access
server.use(restify.CORS());
restify.CORS.ALLOW_HEADERS.push("authorization");
restify.CORS.ALLOW_HEADERS.push("withcredentials");
restify.CORS.ALLOW_HEADERS.push("x-requested-with");
restify.CORS.ALLOW_HEADERS.push("x-forwarded-for");
restify.CORS.ALLOW_HEADERS.push("x-customheader");
restify.CORS.ALLOW_HEADERS.push("user-agent");
restify.CORS.ALLOW_HEADERS.push("keep-alive");
restify.CORS.ALLOW_HEADERS.push("host");
restify.CORS.ALLOW_HEADERS.push("accept");
restify.CORS.ALLOW_HEADERS.push("connection");
restify.CORS.ALLOW_HEADERS.push("content-type");

server.on('after', restify.auditLogger({log: log}));

// API Routes

// Add Promos
// Scope Required: 'promos:create'
server.post({path: '/promos'},
  //passport.authenticate('oauth2-jwt-bearer', { session: false , scopes: ['promos:create']}),
  function respond(req, res, next) {
  var promo = req.params;
  //Set Promo dates
  promo.created = new Date();
  promo.lastUpdated = new Date();
  promo.startDate = new Date();
  var endTime = new Date();
  var validFor = promo.validFor;
  if(validFor == null) { validFor = 30; }
  promo.endDate = new Date(endTime.setDate(endTime.getDate() + validFor));
  if(promo.target == null) { promo.target = "EVERYBODY"; }

  // Save to DB
  var addPromo = promos.insert( promo );
  try {
    res.send(201, promo);
  } catch (err) { res.send(400, err); }

  return next();
});

// Get all Promos
// Scope Required: 'promos:read'
server.get({path: '/promos'},
  //passport.authenticate('oauth2-jwt-bearer', { session: false , scopes: ['promos:read']}),
  function respond(req, res, next) {
    var query = promos.chain().find({}).simplesort('code').data();
    res.send(200, query);

    return next();
  });

// Search Promos
// Scope Required: 'promos:read'
server.get({path: '/promos/:filter'},
  //passport.authenticate('oauth2-jwt-bearer', { session: false , scopes: ['promos:read']}),
  function respond(req, res, next) {
    var query = promos.chain().find(
      {
        $or: [
          {'code' : req.params.filter},
          {'target' : req.params.filter}
        ]
      }).data();
    console.log("\n\nPromos: " + query + "\n\n");
    res.send(200, query);

    return next();
  });

// Delete promo
// Scope Required: 'promos:delete'
server.del({path: '/promos/:code'},
  //passport.authenticate('oauth2-jwt-bearer', { session: false, scopes: ['promos:cancel'] }),
  function response(req, res, next) {
    var removePromo = promos.find({'code' : req.params.code});
    //var removePromo = promos.get(req.params.code);
    try {
      promos.remove(removePromo);
      res.send(204);
    } catch (err) { res.send(404, err);  }

    return next();
  });

// Delete all from db
server.get({path: '/delete'},
  //passport.authenticate('oauth2-jwt-bearer', { session: false, scopes: ['promos:cancel'] }),
  function respond(req, res, next) {
    var removeAll = promos.chain().remove();
    console.log("Removed all entries from database");
    res.send(204);

    return next();
  });

var port = (process.env.PORT || 5000);
server.listen(port, '0.0.0.0', function() {
  log.info('listening: %s', server.url);
});
