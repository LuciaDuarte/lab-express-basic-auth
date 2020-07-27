const routeAuthenticationGuard = (request, response, next) => {
  if (request.session) {
    next();
  } else {
    next(new Error('User is not authenticated'));
  }
};

module.exports = routeAuthenticationGuard;
