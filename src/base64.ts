export const base64: any = {}

// tslint:disable-next-line strict-type-predicates
if (typeof btoa === 'undefined') {
  base64.btoa = function btoa(b: any) {
    return Buffer.from(b, 'binary').toString('base64')
  }
} else {
  base64.btoa = btoa
}

// tslint:disable-next-line strict-type-predicates
if (typeof atob === 'undefined') {
  base64.atob = function atob(b: any) {
    return Buffer.from(b, 'base64').toString('binary')
  }
} else {
  base64.atob = atob
}
