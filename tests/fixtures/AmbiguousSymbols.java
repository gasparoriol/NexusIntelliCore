class OuterHandler {
  void onCommandSuccess(String msg) {
    System.out.println("outer-1:" + msg);
  }

  void onCommandSuccess(int code) {
    System.out.println("outer-2:" + code);
  }

  class AuthListener {
    void onCommandSuccess(String msg) {
      System.out.println("inner:" + msg);
    }
  }
}
