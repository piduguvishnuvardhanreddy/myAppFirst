const resetTokens = {}; // token: { userId, expires }

const storeToken = (token, userId) => {
  resetTokens[token] = {
    userId,
    expires: Date.now() + 1000 * 60 * 15 // 15 minutes
  };
};

const getTokenData = (token) => {
  const data = resetTokens[token];
  if (!data || data.expires < Date.now()) {
    delete resetTokens[token];
    return null;
  }
  return data;
};

const deleteToken = (token) => {
  delete resetTokens[token];
};

module.exports = { storeToken, getTokenData, deleteToken };
