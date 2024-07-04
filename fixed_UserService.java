public boolean login(String username, String passwd){
    return !userDao.find(username, passwd).isEmpty();
}
