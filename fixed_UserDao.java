public List<User> find(String username, String passwd){
    String sql = "SELECT * FROM t_user WHERE username='" + username + "' and passwd='" + passwd + "'";
    return mysql.queryForList(sql, User.class);
}
